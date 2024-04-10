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

static bool check_verbose_arg(char **argv, int argc)
{
    for(int i = 0; i < argc; i++)
    {
        if (i == argc - 1 && argv[i][0] == '-' && argv[i][1] == 'v')
            return (true);
    }
    return (false);
}

static bool check_interface(char *interface, struct sockaddr_ll *network_interface)
{
    struct ifaddrs *all_interfaces, *temp;

    if ((getifaddrs(&all_interfaces)) != 0)
        return (printf("Fail getifaddrs: %s\n", strerror(errno)), false);
    temp = all_interfaces;
    while(temp != NULL)
    {
        if (strcmp(temp->ifa_name, interface) == 0)
        {
            network_interface->sll_family = AF_PACKET;
            network_interface->sll_ifindex = if_nametoindex(temp->ifa_name);
            network_interface->sll_halen = ETH_ALEN;
            network_interface->sll_hatype = ARPHRD_ETHER;
            network_interface->sll_protocol = htons(ETH_P_ARP);
            memset(&network_interface->sll_addr, 0xFF, ETH_ALEN);
            printf("\033[1;32mInterface %s find\033[0m\n", temp->ifa_name);//verbose
            fflush(stdout);
            break;
        }
        temp = temp->ifa_next;
    }
    if (temp == NULL)
        return (printf("Error: Interface %s not found\n", interface), false);
    freeifaddrs(all_interfaces);
    return (true);
}

bool parse_arg(char **argv, int argc, struct data_arg *arg_addr, struct sockaddr_ll *network_interface)
{
    memset(arg_addr, 0, sizeof(struct data_arg));
    memset(network_interface, 0, sizeof(struct sockaddr_ll));
    if (argc == 5 || argc == 6)
    {
        if (!parse_ip(argv[1], arg_addr->arg_ip_addr_src) || !parse_ip(argv[3], arg_addr->arg_ip_addr_target) || !parse_mac(argv[2]) || !parse_mac(argv[4]))
            return (false);
        addr_char_to_int(argv[2], arg_addr->arg_mac_addr_src, 16);
        addr_char_to_int(argv[4], arg_addr->arg_mac_addr_target, 16);
        arg_addr->unicast = 1;
        arg_addr->verbose = check_verbose_arg(argv, argc);
    }
    else if (strcmp(argv[1], "-g") == 0 && (argc == 4 || argc == 5))
    {
        if (!parse_ip(argv[2], arg_addr->arg_ip_addr_target) || !check_interface(argv[3], network_interface))
            return (false);
        arg_addr->gratuitous = 1;
        arg_addr->verbose = check_verbose_arg(argv, argc);
    }
    else
        return(printf("Utilisation de ft_malcolm:\nMode unicast \"./ft_malcolm 'adresse ip source' 'adresse mac source' 'adresse ip cible' 'adresse mac cible'\"\nMode gratuitous \"./ft_malcolm -g 'Addresse Ip a usurper'\"\nPour le mode verbose ajouter -v en dernier argument\n"), false);
    return (true);
}