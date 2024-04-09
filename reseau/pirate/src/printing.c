#include "main.h"

/* La fonction ntohs() est utilisée pour convertir les entiers de l'ordre des octets du réseau (big-endian) à l'ordre des octets de l'hôte
(little-endian) en sortie de la trame Ethernet.
        
Après le cast dans la structure 'ether_header', les valeurs sont stockées en big-endian, ce qui signifie que les octets de poids fort sont
stockés à l'adresse mémoire la plus basse. Cependant, notre système utilise une représentation little-endian, où les octets de poids 
faible sont stockés à l'adresse mémoire la plus basse. Par conséquent, pour interpréter correctement le champ 'ether_type' dans la trame Ethernet,
nous utilisons ntohs() pour convertir les octets de big-endian en little-endian.

En utilisant ntohs(), nous nous assurons que nous obtenons la valeur correcte du champ 'ether_type', quel que soit l'endianness de notre système, 
ce qui garantit une interprétation correcte du type de protocole encapsulé dans la trame Ethernet. Je decide de laisser en little-endian
pour ne pas a avoir a convertir au moment de renvoyer le message*/

void print_arp_frame(const struct arp_frame *arp_frame)
{
    printf("\033[1;31mHeader Ethernet\033[0m\n");
    printf("MAC address destination: ");
    for(int i = 0; i < ETH_ALEN; i++)
        printf("%02x ", arp_frame->ether_dest_mac[i]);
    printf("\n");
    printf("MAC address source: ");
    for(int i = 0; i < ETH_ALEN; i++)
        printf("%02x ", arp_frame->ether_src_mac[i]);
    printf("\nProtcol_type (hex): 0x%04x\n\n", ntohs(arp_frame->ether_type));
    int i = 0;
    printf("\033[1;31mARP Content\033[0m\n");
    printf("Hardware_type: 0x%04x\n", ntohs(arp_frame->hardware_type));
    printf("Protocol_type: 0x%04x\n", ntohs(arp_frame->protocole_type));
    printf("Mac_address_size (octect): 0x%02x\n", arp_frame->mac_size);
    printf("IP_address_size (octect): 0x%02x\n", arp_frame->ip_size);
    printf("Operation_code: 0x%04x\n", ntohs(arp_frame->op_code));

    printf("Sender_MAC_address: ");
    for(int j = 0; j < ETH_ALEN; j++)
        printf("%02x ", arp_frame->sender_mac[j]);
    printf("\n");
    printf("Sender_IP_address hex/dec: ");
    for(; i < 3; i++)
        printf("%02x ", arp_frame->sender_ip[i]);
    printf("%02x/", arp_frame->sender_ip[i]);
    i = 0;
    for(; i < 3; i++)
        printf("%d.", arp_frame->sender_ip[i]);
    printf("%d\n", arp_frame->sender_ip[i]);
    
    printf("Target_MAC_address: ");
    for(int j = 0; j < ETH_ALEN; j++)
        printf("%02x ", arp_frame->target_mac[j]);
    printf("\n");
    i = 0;
    printf("Target_IP_address hex/dec: ");
    for(; i < 3; i++)
        printf("%02x ", arp_frame->target_ip[i]);
    printf("%02x/", arp_frame->target_ip[i]);
    i = 0;
    for(; i < 3; i++)
        printf("%d.", arp_frame->target_ip[i]);
    printf("%d\n\n", arp_frame->target_ip[i]);
}

void print_network_interface(struct sockaddr_ll *network_interface)
{
    printf("\033[1;31mNetwork Interface Information\033[0m\n");
    printf("Network_interface_family: %s\n", (network_interface->sll_family == AF_PACKET) ? "AF_PACKET" : "AUTRES" );
    printf("Network_interface_protocol: %s\n", (htons(network_interface->sll_protocol) == ETH_P_ARP) ? "ARP" : "AUTRES");
    printf("Network_interface_ifindex: %d\n", network_interface->sll_ifindex);
    printf("Network_interface_hatype: %s\n", (network_interface->sll_hatype == ARPHRD_ETHER) ? "Address Ethernet" : (network_interface->sll_hatype == ARPHRD_IEEE80211) ? "Address WiFI" : (network_interface->sll_hatype == ARPHRD_LOOPBACK) ? "LoopBackcInterface" : "");
    printf("Network_interface_pktype Packet %s\n", (network_interface->sll_pkttype == PACKET_HOST) ? "for: local host" : (network_interface->sll_pkttype == PACKET_BROADCAST) ? " for: broadcast" : (network_interface->sll_pkttype == PACKET_MULTICAST) ? "for: multicast" : (network_interface->sll_pkttype == PACKET_OTHERHOST) ? "for: other interfaces on local network" : (network_interface->sll_pkttype == PACKET_OUTGOING) ? ": send by local host" : "");
    printf("Network_interface_halen (size MAC): %d octect\n", network_interface->sll_halen);
    printf("Network_interface_addr (MAC address): ");
    for(int i = 0; i < ETH_ALEN; i++)
        printf("%02x ", network_interface->sll_addr[i]);
    printf("\n\n");
}

void print_trame(char *buf, ssize_t size)
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

void print_information(char *buf, struct network_frame *network_frame_info, ssize_t recv)
{
    printf("-----------------------------------------------\033[1;32mNew ARP Trame recv\033[0m-----------------------------------------------\n");
    printf("\n");
    print_network_interface(&network_frame_info->network_interface);
    print_arp_frame(&network_frame_info->recv_frame);
    print_trame(buf, recv);
    printf("----------------------------------------------------------------------------------------------------------------\n");
    fflush(stdout);
}