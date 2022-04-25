# include <scan.h>
# include <signal.h>
# include <cstdio>
# include <unistd.h>
# include <cstring>


void connect_handler(int signum) {
    return ;
}

int connect_timeout(int sock, const sockaddr* paddr, socklen_t salen, int nsecs) {
    int result;
    signal(SIGALRM, connect_handler);
    if (ualarm(nsecs, 0)) {
        printf("Error! Alarm already set");
    }
    result = connect(sock, paddr, salen);

    alarm(0);
    signal(SIGALRM, connect_handler);

    close(sock);
    return result; 
}

int scan_port(char* host, int port) {
    sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    int status; 

	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("Create socket error");
		return 1;
	}

	addr.sin_family = AF_INET;
	inet_pton(AF_INET, host, &addr.sin_addr);
	addr.sin_port = htons(port);

	status = connect_timeout(sock, (struct sockaddr*)&addr, sizeof(addr), 10);

	return status;
}