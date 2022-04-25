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

int main() {
    signal_init(); 
    CLEARSCREEN(); 
    
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    
    AddPollfd(STDIN_FILENO, POLL_IN, stdin_handler);
    AddPollfd(sock, POLL_IN, socket_handler);
    // sniffer_logger::setLogFile(LOG_FILE);
    int res; 
    while (true) {
        res = poll(pollfds, cnt, time_out) ;
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
    // sniffer_logger::closeLogFile();
    return 0; 
}