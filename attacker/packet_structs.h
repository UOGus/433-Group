#include <pcap.h>

struct ethheader {
    unsigned char  ether_dhost[6];
    unsigned char  ether_shost[6];
    unsigned short ether_type;
};


struct ipheader {
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address
  struct  in_addr    iph_destip;   //Destination IP address
};

struct tcpheader {
    u_short tcp_sport;               
    u_short tcp_dport;               
    u_int   tcp_seq;               
    u_int   tcp_ack;                 
    u_char  tcp_offx2;
    #define TH_OFF(th) (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char  tcp_flags;
    #define TH_FIN  0x01
    #define TH_SYN  0x02
    #define TH_RST  0x04
    #define TH_PUSH 0x08
    #define TH_ACK  0x10
    #define TH_URG  0x20
    #define TH_ECE  0x40
    #define TH_CWR  0x80
    #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short tcp_win;              
    u_short tcp_sum;               
    u_short tcp_urp;
};

struct pseudo_tcp
{
        unsigned saddr, daddr; // src and dst address 
        unsigned char mbz;  // field always set to zero just here to alignment of the struct in terms of bytes 
        unsigned char ptcl; // protocol tcp
        unsigned short tcpl;  // tcp length of header and payload
        struct tcpheader tcp; // actually tcp header 
        char payload[1500]; 
};
