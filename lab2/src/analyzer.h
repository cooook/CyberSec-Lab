# ifndef __ANALYZER_H__
# define __ANALYZER_H__
# endif
# include <unistd.h>
# include <fcntl.h>
# include <stdlib.h>
# include <stdio.h>

# define BUFFER_SIZE 0x1000


struct protocol_counter {
    int tcp;
	int udp;
	int icmp;
	int igmp;
	int others;
    int total; 
} ;

class sniffer_logger ;

class ip_sniffer;

class tcp_sniffer;

class udp_sniffer;

class icmp_sniffer;

class igmp_sniffer;


void Process(const char *buffer, int size);