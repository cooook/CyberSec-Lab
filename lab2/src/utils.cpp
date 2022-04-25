# include <utils.h>
# include <stdio.h> 
# include <sys/socket.h>
# include <stdlib.h>
# include <cstring> 
# include <analyzer.h>

void exit_handler(int signum) {
    printf("Abort by user.\n");
    exit(0);
}

void stdin_handler(int fd) {
    char buffer[0x10];
    read(0, buffer, 0x10);
    if (strncmp(buffer, "q", 1) == 0) {
        exit_handler(0);
    }
}

void socket_handler(int sock) {
    static char buffer[0x10000];
    int size = recv(sock, buffer, sizeof(buffer) - 1, 0);
    Process(buffer, size);
}