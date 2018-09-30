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

typedef struct TCPHeader {
    uint16_t SrcPort;
    uint16_t DstPort;
    uint32_t SN;
    uint32_t AN;
    uint8_t Offset : 4;
    uint8_t Reserved : 4;
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
}TCPH;


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
          struct nfq_data *nfa, void *data)
{
    u_int32_t id;
    int payload;
    uint8_t *value;
    struct nfqnl_msg_packet_hdr *packet_hdr;
    IPH *resip;
    TCPH *restcp;

    packet_hdr = nfq_get_msg_packet_hdr(nfa);
    id = ntohl(packet_hdr->packet_id);
    payload = nfq_get_payload(nfa, &value);
    resip = (IPH *)value;

    if(resip->Protocol == 0x06){
        restcp = (TCPH *)(value + (resip->IHL * 4));
        if(ntohs(restcp->SrcPort) ==80){
            value += restcp->Offset;
            smatch m;
            if(regex_search(value, m, "hacking")){
                regex_replace(value, "hacking", "hooking");
            }
        }
    }


}


int main(int argc, char **argv){
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));
    uint8_t data;

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

