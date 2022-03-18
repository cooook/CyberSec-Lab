# include <ip_parser.h>
# include <cstring> 
# include <stdlib.h>
# include <stdio.h>


void parser(char *command, char*& ip, int &netmask) {
    ip = strtok(command, "/");
    char *mask = strtok(NULL, "/");
    netmask = atoi(mask);
}

int fromIP2int(char *ip) {
    int temp[4]; 
    sscanf(ip, "%d.%d.%d.%d", &temp[0], &temp[1], &temp[2], &temp[3]);
    return temp[0] << 24 | temp[1] << 16 | temp[2] << 8 | temp[3];
}