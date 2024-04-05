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
static bool parse_ip(char *str_ip)
{
    char ip[16];
    int ret = inet_pton(AF_INET, str_ip, ip);
    if(ret != 1)
        return (printf("Invalid IP address (%s)\n", str_ip), false);
    return (true);
}

bool parse_arg(char **argv)
{
    if (!parse_ip(argv[1]) || !parse_ip(argv[3]) || !parse_mac(argv[2]) || !parse_mac(argv[4]))
        return (false);
    return (true);
}