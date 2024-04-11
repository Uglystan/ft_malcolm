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
#include <signal.h>
#include <net/if.h>

extern int sockRaw;

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

struct data_arg {
    uint8_t arg_mac_addr_src[ETH_ALEN];
    uint8_t arg_ip_addr_src[4];
    uint8_t arg_mac_addr_target[ETH_ALEN];
    uint8_t arg_ip_addr_target[4];
    int verbose;
    int gratuitous;
    int unicast;
};

struct network_frame {
    struct sockaddr_ll network_interface;
    struct arp_frame recv_frame;
    struct arp_frame send_frame;
    struct data_arg arg_addr;
};

size_t ft_strlen(const char *str);
void ft_strcpy(char *dest, const char *src);
void converToBinary(char *data, ssize_t length);
void binaryToHex(char *binStr);
void print_information(char *buf, struct network_frame *network_frame_info, ssize_t recv);
void print_network_interface(struct sockaddr_ll *network_interface);
void print_arp_frame(const struct arp_frame *arp_frame, char *msg);
bool parse_arg(char **argv, int argc, struct data_arg *arg_addr, struct sockaddr_ll *network_interface);
bool create_frame_unicast_request(struct arp_frame *send_frame, struct arp_frame *recv_frame, char *ip, int verbose);
bool create_frame_gatuitous(struct arp_frame *send_frame, char *ip, int verbose);
int pos_ascii_hex_int_to_int(char *str, size_t base_size);
void addr_char_to_int(char *address, uint8_t *mac_address, size_t base);
ssize_t recv_frame(int *sockRaw, char *buf, struct network_frame *network_frame_info, socklen_t *len);
int send_frame(int sockRaw, struct network_frame *network_frame_info);
#endif