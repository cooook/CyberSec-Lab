# include <ip_parser.h>
# include <scan.h> 
# include <cstring>
# include <stdlib.h>
# include <stdio.h>
# include <netdb.h>

# define byte(_, __) ((_) >> (8 * __) & 0xff)


int main(int argc, char** argv) {
    if (argc < 4) {
        printf("Usage: %s <ip>/<netmask> <start_port> <end_port>\n", argv[0]);
        printf("example: %s 127.0.0.1/24 0 65535\n", argv[0]);
        exit(0);
    }

    char *command = strdup(argv[1]);
    char *host;
    char buf[0x20];
    int netmask, ip, start_port, end_port;

    parser(command, host, netmask);

    netmask = (1 << (32 - netmask)) - 1;
    start_port = atoi(argv[2]);
    end_port = atoi(argv[3]);

    ip = fromIP2int(host);
    ip &= ~netmask;

    int target_ip ;
    // in_addr addr; 
    hostent *phost;
    sockaddr_in addr; 

    for (int i = 1; i <= netmask - 1; ++i) {

        // memset(host, 0, sizeof(host));
        
        target_ip = ip | i;
        sprintf(host, "%d.%d.%d.%d", byte(target_ip, 3), 
            byte(target_ip, 2), byte(target_ip, 1), byte(target_ip, 0));
        inet_pton(AF_INET, host, &addr.sin_addr);
        phost = gethostbyaddr((const char*)&addr.sin_addr, sizeof(addr.sin_addr), AF_INET);
        addr.sin_family = AF_INET;
        if (phost)
            printf("Host: %s\n", phost -> h_name);
        else
            printf("Host: %s\n", host);


        for (int port = start_port; port <= end_port; ++port) {
            addr.sin_port = htons(port);
            if (scan_port(addr) > 0)
                printf("    |-ip:%s port:%d open!\n", host, port);
        }
    }

    free(command);
    return 0; 
}