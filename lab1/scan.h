# ifndef SCAN_H
# define SCAN_H
# include <arpa/inet.h>

int scan_port(const struct sockaddr_in &addr);

# endif