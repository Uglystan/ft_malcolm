#include "main.h"

bool create_frame_unicast_request(struct arp_frame *send_frame, struct arp_frame *recv_frame, char *ip, struct data_arg *arg_addr)
{
    char *test = ip;
    test[0] = 'd';
    ft_memcpy(send_frame->ether_dest_mac, recv_frame->ether_src_mac, ETH_ALEN);
    // if (!(get_my_address_MAC(send_frame->ether_src_mac, ip)))
    //     return (false);
    ft_memcpy(send_frame->ether_src_mac, arg_addr->arg_mac_addr_src, ETH_ALEN);
    send_frame->ether_type = htons(0x0806);
    send_frame->hardware_type = htons(0x0001);
    send_frame->ip_size = 0x04;
    send_frame->mac_size = 0x06;
    send_frame->op_code = htons(0x0002);
    send_frame->protocole_type = htons(0x0800);
    ft_memcpy(send_frame->sender_ip, recv_frame->target_ip, 4);
    // if (!(get_my_address_MAC(send_frame->sender_mac, ip)))
    //     return (false);
    ft_memcpy(send_frame->sender_mac, arg_addr->arg_mac_addr_src, ETH_ALEN);
    ft_memcpy(send_frame->target_ip, recv_frame->sender_ip, 4);
    ft_memcpy(send_frame->target_mac, recv_frame->sender_mac, ETH_ALEN);
    return (true);
}
