#include <stdio.h>
#include <stdlib.h>
#include "packet_structs.h"

//pcap handler
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
        
        switch(ip->iph_protocol) {
            case IPPROTO_TCP:
                printf("%s\n", inet_ntoa(ip->iph_sourceip));
                // const u_char *payload = packet + sizeof(struct ethheader) + sizeof(struct ipheader);
                // int payload_size = header->len - (payload - packet); 
                // printf("   Protocol: TCP\n");

                // for(int i = 0; i < payload_size; i++){
                //     printf("%c", payload[i]);
                // }

                return;
            case IPPROTO_UDP:
                printf("   Protocol: UDP\n");
                return;
            case IPPROTO_ICMP:
                printf("%s\n", inet_ntoa(ip->iph_sourceip));
                return;
            default:
                printf("   Protocol: others\n");
                return;
        }
    }
    
}

int main(){
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;

    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);

    pcap_compile(handle, &fp, filter_exp, 0, net);
    if (pcap_setfilter(handle, &fp) !=0) {
        pcap_perror(handle, "Error:");
        exit(EXIT_FAILURE);
    }

    pcap_loop(handle, -1, got_packet, NULL);
    pcap_close(handle);
    return 0;
}

