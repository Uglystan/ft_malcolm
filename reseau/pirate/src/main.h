#ifndef MAIN_H
# define MAIN_H

# define SIZE_MAX_ARP 1500

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <ifaddrs.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include <netpacket/packet.h>
#include <net/if_arp.h>
#include <netinet/ether.h>

size_t ft_strlen(const char *str);
void ft_strcpy(char *dest, const char *src);

#endif