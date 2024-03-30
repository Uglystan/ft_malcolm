#ifndef MAIN_H
# define MAIN_H

# define SIZE_MAX_ARP 1500


#include <stdint.h>
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
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>

struct arp_content {
    uint16_t hardware_type;
    uint16_t protocole_type;
    uint8_t mac_size;
    uint8_t ip_size;
    uint16_t op_code;
    uint8_t sender_mac[ETH_ALEN];
    uint8_t sender_ip[4];
    uint8_t target_mac[ETH_ALEN];
    uint8_t target_ip[4];
};

struct network_frame {
    struct sockaddr_ll *network_interface;
    struct ether_header *ethernet_header;
    struct arp_content *arp_content;
};

size_t ft_strlen(const char *str);
void ft_strcpy(char *dest, const char *src);
void converToBinary(char *data, int length);
void binaryToHex(char *binStr);
void print_network_interface(const struct sockaddr_ll *network_interface);
void print_ethernet_header(const struct ether_header *ethernet_header);
void print_arp_content(const struct arp_content *arp_content);
void print_trame(char *buf, int size);

#endif