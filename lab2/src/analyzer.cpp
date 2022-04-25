# include <cstring> 
# include <stdio.h>
# include <utils.h>
# include <display.h>
# include <analyzer.h>
# include <arpa/inet.h>
# include <netinet/ip.h>
# include <netinet/udp.h>
# include <netinet/tcp.h>
# include <netinet/ip_icmp.h>

protocol_counter counter; 

class sniffer_logger {
public:
    static FILE* fd;
    virtual void analyzer(const char* buffer, int len) = 0;
    void analyzeMac(const char* buffer, int len) ;

    void hexPrint(const char* buffer, int len);
    // static void setLogFile(const char *filePath) { fd = fopen(filePath, "w"); }
    // static void closeLogFile() { fclose(fd);  }
} ;

class ip_sniffer:public sniffer_logger {
public:
    virtual void analyzer(const char* buffer, int len); 
} ; 

class tcp_sniffer:public ip_sniffer {
public:
    virtual void analyzer(const char* buffer, int len); 
} ; 

class udp_sniffer:public ip_sniffer {
public:
    virtual void analyzer(const char* buffer, int len); 
} ; 

class icmp_sniffer:public ip_sniffer {
public:
    virtual void analyzer(const char* buffer, int len); 
} ; 

class igmp_sniffer:public ip_sniffer {
public:
    virtual void analyzer(const char* buffer, int len); 
} ; 

# define ProcessSniffer(buffer, len, protocol)    {                 \
    protocol##_sniffer* sniffer = new protocol##_sniffer;           \
    sniffer->analyzeMac(buffer, len);                               \
    sniffer->analyzer(buffer + 14, len);                            \
    delete sniffer;                                                 \
    sniffer = NULL;                                                 \
}

void Process(const char *buffer, int len) {
    struct iphdr *ip_header = (struct iphdr*)(buffer + 14); 
    ++ counter.total;
    switch (ip_header -> protocol)
    {
    case 1:  // ICMP
        ++ counter.icmp;
        ProcessSniffer(buffer, len, icmp);
        break;
    case 2:  // IGMP
        ++ counter.igmp;
        ProcessSniffer(buffer, len, igmp);
        break;
    case 6:  // TCP
        ++ counter.tcp;
        ProcessSniffer(buffer, len, tcp);
        break; 
    case 17: // UDP
        ++ counter.udp;
        ProcessSniffer(buffer, len, udp);
        break;
    default:
        ++ counter.others;
        break;
    }
    showtime();
    printf("TCP:%4d    UDP:%4d    ICMP:%4d    IGMP:%4d    Others:%4d    Total:%d\n",
        counter.tcp, counter.udp, counter.icmp, counter.igmp, counter.others, counter.total);
}

void sniffer_logger::analyzeMac(const char *buffer, int len) {
    if (len < 14) {
        printf("Error packet!\n");
        return ;
    }
    fprintf(fd, "Destination MAC: ");
    for (int i = 0; i < 6; ++i)
        fprintf(fd, "%02x%c", (unsigned int)buffer[i], " \n"[i == 5]);
    buffer += 6;
    fprintf(fd, "Source MAC: ");
    for (int i = 0; i < 6; ++i)
        fprintf(fd, "%02x%c", (unsigned int)buffer[i], " \n"[i == 5]);
    buffer += 6;
    fprintf(fd, "frame length: ");
    fprintf(fd, "%d\n", *(unsigned short*)(buffer));
    buffer += 2;
}

void sniffer_logger::hexPrint(const char *buffer, int len) {
    for (int i = 0; i < len; ++i)
        fprintf(fd, "%02x%c", (unsigned int)buffer[i], " \n"[i % 16 == 0 || i == len - 1]);
}

void ip_sniffer::analyzer(const char* buffer, int len) {
    analyzeMac(buffer, len);
    iphdr *ip_header = (iphdr*) buffer;
    sockaddr_in src, dst; 
    memset(&src, 0, sizeof(src));
    memset(&dst, 0, sizeof(dst));
    src.sin_addr.s_addr = ip_header->saddr;
    dst.sin_addr.s_addr = ip_header->daddr;

    fprintf(fd, "\nIP Header\n");
    fprintf(fd, "   |-IP Version           : %u\n", (unsigned int) ip_header -> version);
    fprintf(fd, "   |-IP Header Length     : %u Bytes\n", (unsigned int) ip_header -> ihl * 4);
    fprintf(fd, "   |-Type Of Service      : %u\n", ip_header -> tos);
    fprintf(fd, "   |-IP Total Length      : %u Bytes(size of Packet)\n",ntohs(ip_header->tot_len));
    fprintf(fd, "   |-Identification       : %u\n",ntohs(ip_header->id));
    fprintf(fd, "   |-TTL                  : %u\n",(unsigned int)ip_header->ttl);
    fprintf(fd, "   |-Protocol             : %u\n",(unsigned int)ip_header->protocol);
    fprintf(fd, "   |-Checksum             : %u\n",ntohs(ip_header->check));
    fprintf(fd, "   |-Source IP            : %s\n",inet_ntoa(src.sin_addr));
    fprintf(fd, "   |-Destination IP       : %s\n",inet_ntoa(dst.sin_addr));
}


void tcp_sniffer::analyzer(const char* buffer, int len) {
    iphdr* ip_header;
    tcphdr* tcp_header; 
    ip_header = (iphdr*)buffer;
    int ip_pkg_len = ip_header -> ihl << 2;
    tcp_header = (tcphdr*)(buffer + ip_pkg_len);
    // ip_sniffer::analyzer(buffer, len);
    fprintf(fd, "\nTCP Header\n");
    fprintf(fd, "   |-Source Port          : %u\n",ntohs(tcp_header->source));
    fprintf(fd, "   |-Destination Port     : %u\n",ntohs(tcp_header->dest));
    fprintf(fd, "   |-Sequence Number      : %u\n",ntohl(tcp_header->seq));
    fprintf(fd, "   |-Acknowledge Number   : %u\n",ntohl(tcp_header->ack_seq));
    fprintf(fd, "   |-Header Length        : %u Bytes\n" ,(unsigned int)tcp_header->doff*4);
    fprintf(fd, "   |-Urgent Flag          : %u\n",(unsigned int)tcp_header->urg);
    fprintf(fd, "   |-Acknowledgement Flag : %u\n",(unsigned int)tcp_header->ack);
    fprintf(fd, "   |-Push Flag            : %u\n",(unsigned int)tcp_header->psh);
    fprintf(fd, "   |-Reset Flag           : %u\n",(unsigned int)tcp_header->rst);
    fprintf(fd, "   |-Synchronise Flag     : %u\n",(unsigned int)tcp_header->syn);
    fprintf(fd, "   |-Finish Flag          : %u\n",(unsigned int)tcp_header->fin);
    fprintf(fd, "   |-Window               : %u\n",ntohs(tcp_header->window));
    fprintf(fd, "   |-Checksum             : %u\n",ntohs(tcp_header->check));
    fprintf(fd, "   |-Urgent Pointer       : %u\n",tcp_header->urg_ptr);
    fprintf(fd,"\n                        DATA Dump                         \n");
  
    fprintf(fd,"IP Header\n");
    hexPrint(buffer, ip_pkg_len);
  
    fprintf(fd,"TCP Header\n");
    hexPrint(buffer + ip_pkg_len, tcp_header->doff*4);
  
    fprintf(fd,"Data Payload\n");
    hexPrint(buffer + ip_pkg_len + tcp_header -> doff * 4,
        len - tcp_header -> doff * 4 - ip_header -> ihl * 4);
}


void udp_sniffer::analyzer(const char* buffer, int len) {
    iphdr* ip_header;
    udphdr* udp_header; 
    ip_header = (iphdr*)buffer;
    int ip_pkg_len = ip_header -> ihl << 2;
    udp_header = (udphdr*)(buffer + ip_pkg_len);
    // ip_sniffer::analyzer(buffer, len);
    fprintf(fd,"\nUDP Header\n");

    fprintf(fd, "   |-Source Port          : %u\n",         ntohs(udp_header->source));
    fprintf(fd, "   |-Destination Port     : %u\n",         ntohs(udp_header->dest));
    fprintf(fd, "   |-UPD Header Length    : %u Bytes\n",   ntohs(udp_header->len));
    fprintf(fd, "   |-UPD Check Sum        : %u\n",         ntohs(udp_header->check));

    fprintf(fd,"IP Header\n");
    hexPrint(buffer, ip_pkg_len);
  
    fprintf(fd,"TCP Header\n");
    hexPrint(buffer + ip_pkg_len, udp_header -> len);
  
    fprintf(fd,"Data Payload\n");
    hexPrint(buffer + ip_pkg_len + udp_header -> len,
        len - udp_header -> len - ip_header -> ihl * 4);
}


void icmp_sniffer::analyzer(const char* buffer, int len) {
    
}


void igmp_sniffer::analyzer(const char* buffer, int len) {
    
}