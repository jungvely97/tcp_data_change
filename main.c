#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>        /* for NF_ACCEPT */
#include <errno.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <regex>
#include <string.h>
#include <string>
#include <iostream>

using namespace std;

#pragma pack(push, 1)
typedef struct  {
    uint8_t IHL : 4;
    uint8_t Version : 4;
    uint8_t TOS;
    unsigned short TotalLen;
    unsigned short Identifi;
    uint8_t Flagsx : 1;
    uint8_t FlagsD : 1;
    uint8_t FlagsM : 1;
    uint8_t FO1 : 5;
    uint8_t FO2;
    uint8_t TTL;
    uint8_t Protocol;
    uint16_t HeaderCheck;
    struct in_addr SrcAdd;
    struct in_addr DstAdd;
}IPH;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct TCPHeader {
    uint16_t SrcPort;
    uint16_t DstPort;
    uint32_t SN;
    uint32_t AN;
    uint8_t Reserved : 4;
    uint8_t Offset : 4;
    uint8_t FlagsC : 1;
    uint8_t FlagsE : 1;
    uint8_t FlagsU : 1;
    uint8_t FlagsA : 1;
    uint8_t FlagsP : 1;
    uint8_t FlagsR : 1;
    uint8_t FlagsS : 1;
    uint8_t FlagsF : 1;
    uint16_t Window;
    uint16_t Check;
    uint16_t UP;
}TCPH; //Little-endian
#pragma (pop)

#pragma pack(push, 1)
typedef struct Pseudoheader {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint8_t reserved = 0;  // 항상 0
    uint8_t protocal;
    uint16_t tcp_len;  //tcp 길이 (header + data)
}PseudoH;
#pragma (pop)

void dump(unsigned char *pkt, int len){

    printf("\n");
    for(int i =0; i< len; i++){
    printf("%02x ", pkt[i]);
    }
    printf("\n");
}

uint16_t calculate(uint16_t *data, uint32_t len){
    uint32_t sum = 0;

    while(1){
        if(len == 0 || len == 1) break;
        sum += ntohs(*data++);
        len -= 2;
    } if(len == 1) sum+=ntohs((uint8_t)*data);

    sum = (sum >> 16) + (sum & 0xffff);

    return sum;
}

uint16_t checksum( uint8_t *value, uint32_t payload){
    PseudoH pseudo;
    IPH *resip;
    TCPH *restcp;
    uint16_t pseudo_result, tcp_result;
    uint32_t total_result;

    resip = (IPH *)value;
    restcp = (TCPH *)(value + resip->IHL *4);
    memcpy(&pseudo.src_ip, &resip->SrcAdd, sizeof(pseudo.src_ip));
    memcpy(&pseudo.dst_ip, &resip->DstAdd, sizeof(pseudo.dst_ip));
    pseudo.protocal = resip->Protocol;
    pseudo.tcp_len = htons(payload - (resip->IHL *4));
    restcp->Check = 0x00;

    pseudo_result = calculate((uint16_t *)&pseudo, sizeof(pseudo));
    tcp_result = calculate((uint16_t *)restcp, ntohs(pseudo.tcp_len));

    total_result = pseudo_result + tcp_result;
    total_result = (total_result >> 16) + (total_result & 0xffff);
    restcp->Check = (uint16_t)(ntohs(~total_result));

    return ntohs(~total_result);
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
          struct nfq_data *nfa, void *data)
{
    u_int32_t id;
    uint32_t payload;
    uint8_t *value;
    struct nfqnl_msg_packet_hdr *packet_hdr;
    IPH *resip;
    TCPH *restcp;
    bool verdict = false;

    packet_hdr = nfq_get_msg_packet_hdr(nfa);
    id = ntohl(packet_hdr->packet_id);
    payload = nfq_get_payload(nfa, &value);
    resip = (IPH *)value;
    if(resip->Protocol == 0x06){
        value += resip->IHL *4;
        restcp = (TCPH *)value;
        if(ntohs(restcp->SrcPort) ==80 ){
            value += (restcp->Offset * 4);
            smatch m;
            string http = (char *)value;
            regex before("hacking");

            if(regex_search(http, m, before)){
                http = regex_replace(http, before, "hooking");
                memcpy(value, http.c_str(), strlen(http.c_str()));
                cout << value;
                value = value - (resip->IHL *4 + restcp->Offset * 4);
                checksum(value, payload);

                verdict = true;
            }
        }
    }

    if(verdict){
        printf("success!\n");
        return nfq_set_verdict(qh, id, NF_ACCEPT, payload, value);
    }else return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

}


int main(int argc, char **argv){
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h,  0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
           // printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}

