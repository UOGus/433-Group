#include <stdio.h>
#include <stdlib.h>
#include "packet_structs.h"
#include <time.h>

int tcp_syn_attempts = 0;
time_t last_time;
int interval; 


int check_time_interval(time_t *last_time) {
    time_t current_time = time(NULL);
    if (difftime(current_time, *last_time) >= interval) {
        printf("SYN Attempts in the last %d seconds: %d\n", interval,tcp_syn_attempts);
        *last_time = current_time;  
        return 1;
    }
    return 0;
}


void print_tcp_flags(struct tcpheader *tcp) {
    printf("TCP Flags: ");
    if (tcp->tcp_flags & TH_FIN)  printf("FIN ");
    if (tcp->tcp_flags & TH_SYN)  printf("SYN ");
    if (tcp->tcp_flags & TH_RST)  printf("RST ");
    if (tcp->tcp_flags & TH_PUSH) printf("PSH ");
    if (tcp->tcp_flags & TH_ACK)  printf("ACK ");
    if (tcp->tcp_flags & TH_URG)  printf("URG ");
    if (tcp->tcp_flags & TH_ECE)  printf("ECE ");
    if (tcp->tcp_flags & TH_CWR)  printf("CWR ");
    printf("\n");
}

//pcap handler
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

        switch(ip->iph_protocol) {
            case IPPROTO_TCP:
                struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + sizeof(struct ipheader));

                //print_tcp_flags(tcp);
                
                tcp_syn_attempts++;

                // checks if the time interval has passed 
                // we will call both detection algorithms in this if statement
                if(check_time_interval(&last_time)){
                    
                    // reset count of syn attempts for the time interval
                    tcp_syn_attempts = 0; 
                }

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

int main(int argc, char *argv[]){
    if(argc == 2){
        interval = atoi(argv[1]);
    }
    else if(argc > 2){
        printf("Error Usage: ./attack_detection <interval> \nor default to 60 sec interval with no arg\n");
        return 1;
    }
    else{
        interval = 60;
    }

    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    // filter for packets with just tcp syn flag
    // SYN flag in the TCP header has a bit value of 0x02 (binary 00000010)
    char filter_exp[] = "tcp[tcpflags] == 2";
    bpf_u_int32 net;

    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);

    pcap_compile(handle, &fp, filter_exp, 0, net);
    if (pcap_setfilter(handle, &fp) !=0) {
        pcap_perror(handle, "Error:");
        exit(EXIT_FAILURE);
    }

    last_time = time(NULL);

    pcap_loop(handle, -1, got_packet, NULL);
    pcap_close(handle);
    return 0;
}

// need to compile with flag -lpcap

