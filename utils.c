#include "main.h"

size_t ft_strlen(const char *str)
{
    size_t i = 0;
    for(; str[i] != '\0'; i++)
    {
    }
    return (i);
}

void ft_strcpy(char *dest, const char *src)
{
    size_t i = 0;
    for (; i < ft_strlen(src); i++)
    {
        dest[i] = src[i];
    }
    dest[i] = '\0';
}

// Transform data en binaire
// Je met le bit en position la plus faible et je le compare avec 1 donc je l'extrait et ensuite je le met dans une string d'ou le +48
// Dans cette fonction je vais extraire bit par bit ce que j'ai recu dans recvfrom donc je decale le chaque bit de chaque octect pour le mettre en position la plus faible
// Et ensuite avec le AND 1 je l'extrait et comme je le met dans une chaine de caractere je fais +48
void converToBinary(char *data, int length)
{
    char binTrame[SIZE_MAX_ARP];
    int i = 0, k = 0;
    for (; i < length; ++i) {
        for (int j = 7; j >= 0; --j) {
            binTrame[k++] = ((data[i] >> j) & 1) + 48;
        }
    }
    binTrame[k] = '\0';
    ft_strcpy(data, binTrame);
}

void binaryToHex(char *binStr)
{
    char hexStr[SIZE_MAX_ARP];
    int i = 0, j = 0, tot = 0;
    while(binStr[i] != '\0')
    {
        if(i % 4 == 0)
            tot = 0;
        if (binStr[i] == '1')
        {
            if((i + 1) % 4 == 0)
                tot = tot + 1;
            else if((i + 1) % 4 == 3)
                tot = tot + 2;
            else if((i + 1) % 4 == 2)
                tot = tot + 4;
            else if((i + 1) % 4 == 1)
                tot = tot + 8;
        }
        if((i + 1) % 4 == 0)
            hexStr[j++] = "0123456789ABCDEF"[tot];
        i++;
    }
    hexStr[j] = '\0';
    ft_strcpy(binStr, hexStr);
}