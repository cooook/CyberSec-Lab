# ifndef __ANALYZER_H__
# define __ANALYZER_H__

# define BUFFER_SIZE 0x1000


struct protocol_counter {
    int tcp;
	int udp;
	int icmp;
	int igmp;
	int others;
    int total; 
} ;

class sniffer_logger {
public:
    static FILE* fd;
    virtual void analyzer(const char* buffer, int len) = 0;
    void analyzeMac(const char* buffer, int len) ;
    void hexPrint(const char* buffer, int len);
    static void setLogFile(const char *filePath) { fd = fopen(filePath, "w"); }
    static void closeLogFile() { fclose(fd);  }
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


void Process(const char *buffer, int size);
# endif