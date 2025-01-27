#include "main.h"

static bool parse_mac(char *str_mac)
{
    if (ft_strlen(str_mac) != 17)
        return (printf("Invalid MAC address (%s)\n", str_mac), false);
    for(int i = 0; str_mac[i] != '\0'; i++)
    {
        if (str_mac[i] == ':' && (i + 1) % 3 == 0)
            continue;
        else if ((str_mac[i] >= '0' && str_mac[i] <= '9') || (str_mac[i] >= 'a' && str_mac[i] <= 'z'))
            continue;
        else
            return (printf("Invalid MAC address (%s)\n", str_mac), false);
    }
    return (true);
}

static bool parse_ip(char *str_ip, uint8_t *ip_address)
{
    int ret = inet_pton(AF_INET, str_ip, ip_address);
    if(ret != 1)
        return (printf("Invalid IP address (%s)\n", str_ip), false);
    return (true);
}

bool use_case_info(void)
{
    printf("Utilisation de ft_malcolm:\nMode unicast \"./ft_malcolm 'adresse ip source' 'adresse mac source' 'adresse ip cible' 'adresse mac cible'\"\n");
    return (false);
}

bool parse_arg(char **argv, int argc, struct data_arg *arg_addr, struct sockaddr_ll *network_interface)
{
    ft_memset(arg_addr, 0, sizeof(struct data_arg));
    ft_memset(network_interface, 0, sizeof(struct sockaddr_ll));
    if (argc == 5) {
        if (!parse_ip(argv[1], arg_addr->arg_ip_addr_src) || !parse_ip(argv[3], arg_addr->arg_ip_addr_target) || !parse_mac(argv[2]) || !parse_mac(argv[4]))
            return (use_case_info());
        addr_char_to_int(argv[2], arg_addr->arg_mac_addr_src, 16);
        addr_char_to_int(argv[4], arg_addr->arg_mac_addr_target, 16);
    }
    else
        return(use_case_info());
    return (true);
}