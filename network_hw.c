#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap.h>

struct etherheader {
  u_char  ether_dhost[6]; /* destination host address */
  u_char  ether_shost[6]; /* source host address */
  u_short ether_type;     /* protocol type (IP, ARP, RARP, etc) */
};

/* IP Header */
struct ipheader {
  u_char   iph_ihl:4, //IP header length
           iph_ver:4; //IP version
  u_char   iph_tos; //Type of service
  u_short iph_len; //IP Packet length (data + header)
  u_short iph_ident; //Identification
  u_short iph_flag:3, //Fragmentation flags
          iph_offset:13; //Flags offset
  u_char   iph_ttl; //Time to Live
  u_char   iph_protocol; //Protocol type
  u_short iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address
  struct  in_addr    iph_destip;   //Destination IP address
};

struct tcpheader {
  u_short sport;   // Source port
  u_short dport;   // Destination port
  u_int seqnum;   // Sequence Number
  u_int acknum;   // Acknowledgement number
  u_char th_off;  // Header length
  u_char flags;   // packet flags
  u_short win;    // Window Size
  u_short crc;    // Header Checksum
  u_short urgptr; // Urgent pointer
};

void got_packet(const u_char *pkt_data) {
  struct etherheader *etherh = (struct etherheader *)pkt_data;
  struct ipheader *iph = (struct ipheader *)(pkt_data + sizeof(struct etherheader)); 
  struct tcpheader *tcph = (struct tcpheader *)(pkt_data + sizeof(struct ipheader) + sizeof(struct etherheader));

  if (iph->iph_protocol != IPPROTO_TCP){
    return;
  }

  u_char *dmac = etherh->ether_dhost;
  u_char *smac = etherh->ether_shost;

  printf("=========== MAC  HEADER =============\n");
  printf("From: %02x:%02x:%02x:%02x:%02x:%02x\n" "To: %02x:%02x:%02x:%02x:%02x:%02x \n",
  smac[0], smac[1], smac[2], smac[3], smac[4], smac[5],
  dmac[0], dmac[1], dmac[2], dmac[3], dmac[4], dmac[5]);

  printf("============ IP  HEADER =============\n");
  printf("From: %s\n", inet_ntoa(iph->iph_sourceip));   
  printf("To: %s\n", inet_ntoa(iph->iph_destip)); 

  printf("============ TCP HEADER =============\n");
  printf("Src Port : %d\n" , ntohs(tcph->sport));
  printf("Dst Port : %d\n" , ntohs(tcph->dport));
  printf("=====================================\n\n");   
}

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
  got_packet(pkt_data);
}

int main(int argc, char **argv) {
    pcap_t *adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int i = 0;
    int no;

    if (pcap_findalldevs(&alldevs, errbuf) < 0) {
        printf("pcap_findalldevs error\n");
        return 1;
    }

    for (d=alldevs; d; d=d->next) {
        printf("%d :  %s\n", ++i, (d->description)?(d->description):(d->name));
    }

    printf("number : ");
    scanf("%d", &no);

    if (!(no > 0 && no <= i)) {
        printf("number error\n");
        return 1;
    }

    for (d=alldevs, i=0; d; d=d->next) {
        if (no == ++i)  break;
    }

    if (!(adhandle= pcap_open_live(d->name, 65536, 1, 1000, errbuf))) {
        printf("pcap_open_live error %s\n", d->name);
        pcap_freealldevs(alldevs);
        return -1;
    }

    pcap_freealldevs(alldevs);

    pcap_loop(adhandle, 0, packet_handler, NULL);

    pcap_close(adhandle);

    return 0;
}
