#include "main.h"

void print_network_interface(const struct sockaddr_ll *network_interface)
{
    printf("\033[1;31mNetwork Interface Information\033[0m\n");
    printf("Network_interface_family: %s\n", (network_interface->sll_family == AF_PACKET) ? "AF_PACKET" : "AUTRES" );
    printf("Network_interface_protocol: %s\n", (htons(network_interface->sll_protocol) == ETH_P_ARP) ? "ARP" : "AUTRES");
    printf("Network_interface_ifindex: %d\n", network_interface->sll_ifindex);
    printf("Network_interface_hatype: %s\n", (network_interface->sll_hatype == ARPHRD_ETHER) ? "Address Ethernet" : (network_interface->sll_hatype == ARPHRD_IEEE80211) ? "Address WiFI" : (network_interface->sll_hatype == ARPHRD_LOOPBACK) ? "LoopBackcInterface" : "");
    printf("Network_interface_pktype Packet %s\n", (network_interface->sll_pkttype == PACKET_HOST) ? "for: local host" : (network_interface->sll_pkttype == PACKET_BROADCAST) ? " for: broadcast" : (network_interface->sll_pkttype == PACKET_MULTICAST) ? "for: multicast" : (network_interface->sll_pkttype == PACKET_OTHERHOST) ? "for: other interfaces on local network" : (network_interface->sll_pkttype == PACKET_OUTGOING) ? ": send by local host" : "");
    printf("Network_interface_halen (size MAC): %d octect\n", network_interface->sll_halen);
    printf("Network_interface_addr (MAC address): %s\n\n", ether_ntoa((struct ether_addr *)network_interface->sll_addr));
}

void print_ethernet_header(const struct ether_header *ethernet_header)
{
    printf("\033[1;31mHeader Ethernet\033[0m\n");
    printf("MAC address destination: ");
    for(int i = 0; i < ETH_ALEN; i++)
        printf("%02x ", ethernet_header->ether_dhost[i]);
    printf("\n");
    printf("MAC address source: ");
    for(int i = 0; i < ETH_ALEN; i++)
        printf("%02x ", ethernet_header->ether_shost[i]);
    printf("\nProtcol_type (hex): 0x%04x\n\n", ntohs(ethernet_header->ether_type));
}

void print_arp_content(const struct arp_content *arp_content)
{
    int i = 0;
    printf("\033[1;31mARP Content\033[0m\n");
    printf("Hardware_type: 0x%04x\n", ntohs(arp_content->hardware_type));
    printf("Protocol_type: 0x%04x\n", ntohs(arp_content->protocole_type));
    printf("Mac_address_size (octect): 0x%02x\n", arp_content->mac_size);
    printf("IP_address_size (octect): 0x%02x\n", arp_content->ip_size);
    printf("Operation_code: 0x%04x\n", ntohs(arp_content->op_code));

    printf("Sender_MAC_address: ");
    for(int j = 0; j < ETH_ALEN; j++)
        printf("%02x ", arp_content->sender_mac[j]);
    printf("\n");
    printf("Sender_IP_address hex/dec: ");
    for(; i < 3; i++)
        printf("%02x ", arp_content->sender_ip[i]);
    printf("%02x/", arp_content->sender_ip[i]);
    i = 0;
    for(; i < 3; i++)
        printf("%d.", arp_content->sender_ip[i]);
    printf("%d\n", arp_content->sender_ip[i]);
    
    printf("Target_MAC_address: ");
    for(int j = 0; j < ETH_ALEN; j++)
        printf("%02x ", arp_content->target_mac[j]);
    printf("\n");
    i = 0;
    printf("Target_IP_address hex/dec: ");
    for(; i < 3; i++)
        printf("%02x ", arp_content->target_ip[i]);
    printf("%02x/", arp_content->target_ip[i]);
    i = 0;
    for(; i < 3; i++)
        printf("%d.", arp_content->target_ip[i]);
    printf("%d\n", arp_content->target_ip[i]);
}

void print_trame(char *buf, int size)
{
    printf("\033[1;31mTrame\033[0m\n");
    converToBinary(buf, size);
    binaryToHex(buf);
    for(size_t i = 1; i <= ft_strlen(buf); i++)
    {
        printf("%c", buf[i - 1]);
        if(i % 2 == 0)
            printf(" ");
    }
    printf("\n");
}