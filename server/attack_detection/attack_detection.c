#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "packet_structs.h"
#include "adaptive_threshold.h"
#include "cusum.h"

FILE *csv_file;  // Global pointer for CSV file

int tcp_syn_attempts = 0;
double average = 0.0;
time_t last_time;
int interval;
int _adaptive_thershold_thershold;

double last_sum = 0.0;  // For CUSUM calculation
double control = 40.0;  // For CUSUM detection

int check_time_interval(time_t *last_time) {
    time_t current_time = time(NULL);
    if (difftime(current_time, *last_time) >= interval) {
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

// PCAP packet handler
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

        switch(ip->iph_protocol) {
            case IPPROTO_TCP:
                struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + sizeof(struct ipheader));

                tcp_syn_attempts++;

                if (check_time_interval(&last_time)) {
                    // Apply Adaptive Threshold algorithm
                    struct AdaptiveResult result = adaptive_threshold_algorithm(average, tcp_syn_attempts);
                    average = result.average;
                    //_adaptive_thershold_thershold=

                    // Apply CUSUM algorithm
                    double sum = cusum(&last_sum, tcp_syn_attempts, average);
                    int alarm = (sum > control) ? 1 : 0;  // Detect anomaly if sum > control

                    // Write results to CSV
                    fprintf(csv_file, "%d,%.2f,%d,%.2f,%d\n", interval++, result.average, alarm, sum, tcp_syn_attempts);
                    fflush(csv_file);  // Ensure the data is written to the file

                    // Reset the count of syn attempts for the time interval
                    tcp_syn_attempts = 0;

                    // Print data to console (for debugging/monitoring purposes)
                    printf("Interval: %d, Adaptive Avg: %.2f, Alarm: %d, CUSUM: %.2f\n", interval, result.average, alarm, sum);
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

int main(int argc, char *argv[]) {
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

    // Open CSV file to write the results
    csv_file = fopen("data.csv", "w");
    if (csv_file == NULL) {
        perror("Error opening CSV file");
        return 1;
    }

    // Write CSV header
    fprintf(csv_file, "Interval,Average,Alarm,CUSUM\n");

    // Initialize pcap
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp[tcpflags] == 2";  // Filter for TCP SYN packets
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

    // Close the CSV file at the end of the program
    fclose(csv_file);

    return 0;
}
