# include <errno.h>
# include <signal.h>
# include <unistd.h>
# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <fcntl.h>
# include <sys/time.h>
# include <sys/types.h>
# include <sys/select.h>
# include <netinet/ip.h>
# include <sys/socket.h>
# include <linux/if_ether.h>
# include <poll.h>
# include <sys/ioctl.h>
# include <net/if.h>
# include <linux/if_packet.h>
# include <net/ethernet.h>


# include <display.h>
# include <utils.h>
# include <analyzer.h>
const int MAX_POLL = 10; 
const int time_out = 1000; 
static int cnt = 0;
static struct pollfd pollfds[MAX_POLL];
void (*handler[MAX_POLL]) (int);


void signal_init() {
    signal(SIGINT, exit_handler);
    signal(SIGABRT, exit_handler);
}

void AddPollfd(int fd, int events, void (*func) (int)) {
    if (cnt == MAX_POLL) {
        printf("Error! Pollfds is full!");
        return ; 
    }
    pollfds[cnt].fd = fd;
    pollfds[cnt].events = events;
    handler[cnt] = func;
    ++cnt; 
}

void bindDevice(int fd, const char *dev) {
    struct sockaddr_ll sl;
    struct ifreq ifr;

    memset(&sl, 0x00, sizeof(sl));
    memset(&ifr, 0x00, sizeof(ifr));
    sl.sll_family = AF_PACKET;
    sl.sll_protocol = htons(ETH_P_ALL);
    strncpy(ifr.ifr_name, dev, sizeof(ifr.ifr_name));
    ioctl(fd, SIOCGIFINDEX, &ifr);
    sl.sll_ifindex = ifr.ifr_ifindex;
    bind(fd, (struct sockaddr *)&sl, sizeof(sl));
}

int main(int argc, const char **argv) {
    if (argc < 2) {
        printf("Usage ./sniffer <device>");
        return 0;
    }

    signal_init(); 
    CLEARSCREEN(); 
    showtime();
    printf("Sniffer Start!\n");
    
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    bindDevice(sock, argv[1]);
    
    AddPollfd(STDIN_FILENO, POLL_IN, stdin_handler);
    AddPollfd(sock, POLL_IN, socket_handler);
    sniffer_logger::setLogFile(LOG_FILE);
    int res; 
    while (true) {
        res = poll(pollfds, cnt, -1) ;
        if (res <= 0) {
            printf("Poll error\n");
            break; 
        }
        else {
            for (int i = 0; i < cnt; ++i)
                if (pollfds[i].revents & POLL_IN)
                    handler[i](pollfds[i].fd);
        }
    }

    close(sock);
    sniffer_logger::closeLogFile();
    return 0; 
}