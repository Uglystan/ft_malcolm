#ifndef MAIN_H
# define MAIN_H

# define SIZE_MAX_ARP 1500

#include <stdbool.h>
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

struct arp_frame {
    uint8_t ether_dest_mac[ETH_ALEN];
    uint8_t ether_src_mac[ETH_ALEN];
    uint16_t ether_type;
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
    struct sockaddr_ll network_interface;
    struct arp_frame recv_frame;
    struct arp_frame send_frame;
};

size_t ft_strlen(const char *str);
void ft_strcpy(char *dest, const char *src);
void converToBinary(char *data, size_t length);
void binaryToHex(char *binStr);
void print_network_interface(struct sockaddr_ll *network_interface);
void print_arp_frame(const struct arp_frame *arp_frame);
void print_trame(char *buf, size_t size);
bool parse_arg(char **argv);
bool create_frame_unicast_request(struct arp_frame *send_frame, struct arp_frame *recv_frame);
int pos_ascii_hex_int_to_int(char *str, size_t base_size);

#endif