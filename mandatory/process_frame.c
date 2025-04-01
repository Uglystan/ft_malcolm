#include "main.h"

ssize_t recv_frame(int *sockRaw, char *buf, struct network_frame *network_frame_info, socklen_t *len)//On passe l'adresse pour que le changement soit detecter avec la fonction qui gere le signal
{
    /* La structure sockaddr_ll fournit des informations sur l'interface réseau à laquelle une trame a été reçue ou à travers laquelle
    elle sera envoyée. Ces informations sont généralement liées à l'interface réseau locale sur la machine où le programme s'exécute
    (ou on recoit le message). La fonction recvfrom prend un type de sockaddr et la taille de se type et le remplie avec les informations*/
        
    ssize_t recv = recvfrom(*sockRaw, buf, SIZE_MAX_ARP, 0, (struct sockaddr *)&network_frame_info->network_interface, len);
    if (recv <= 0)
    {
        if (*sockRaw == -1)//CTRL + C
            return (false);
        else
            return (printf("recvfrom failed : %s\n", strerror(errno)), false);
    }
    
    /* Ici, nous avons un pointeur 'buf' pointant vers les données brutes de la trame. On utilise memcpy pour copier tout ce qu'il y'a dans buf dans
    recv_frame et on fait une copie de la taille de recv_frame*/

    if (recv < (ssize_t)sizeof(struct arp_frame))
        return (printf("Error: Taille du buffer different de la taille d'une frame arp\n"), false);
    ft_memcpy(&network_frame_info->recv_frame, buf, sizeof(struct arp_frame));

    return (recv);
}

/*Envoie de la trame falsifie. Furtivité : En espaçant les envois de trames ARP falsifiées, on reduit le risque d'attirer l'attention. 
Des envois simultanés de trames ARP falsifiées peuvent être détectés plus facilement.
Réussite de l'attaque : En espaçant les envois, on donne aux machines cibles du temps pour mettre à jour leurs caches ARP.
Cela peut augmenter les chances que l'attaque réussisse en trompant efficacement les machines cibles.*/

int send_frame(int sockRaw, struct network_frame *network_frame_info)
{
    int ret = 0;
    ret = sendto(sockRaw, &network_frame_info->send_frame, sizeof(network_frame_info->send_frame), 0, (struct sockaddr *)&network_frame_info->network_interface, sizeof(struct sockaddr_ll));
    return (ret);
}