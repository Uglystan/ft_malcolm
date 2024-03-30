#include "main.h"

//Detaille d'une trame arp (hexadecimal) taille max 1500 octects (a la fin possible padding (0000000000)):
// |------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
// |                                                                      Entete ethernet                                                                                     |                                                                                                                                                                                                                                                                                                                                               Entete ARP                                                                                                                                                                                                                                                                                                                                                            |
// |------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
// | Adresse MAC de Destination du paquet (6 octect) | Adresse MAC de l'emetteur du paquet (6 octect) | Type de protocole encapsule dans la trame (2 octects) (Pour arp 0806) |                 Type de hardware (2 octects) (Ethernet = 0001)            | Type de protocole reseau en general IPv4 (2 octects) (0800 pour IPv4) |  Longueur adresse MAC en octect (1 octect) (en general 06) | Longueur adresse IP en octect (1 octect 04) | Type de message (2 octects) (0001 request 0002 response) | Adresse MAC de l'émetteur de la requête ou de la réponse (6 octect en focntion de precedent) | Adresse IP de l'émetteur de la requête ou de la réponse (4 octect en focntion de precedent) | Adresse MAC du destinataire de la requête ou de la réponse Inconnue et remplie de zéros dans une requête (6 octects) | Adresse IP du destinataire de la requête ou de la réponse (4 octects) |
// |------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
// |                FF FF FF FF FF FF                |               02 42 AC 1A 00 03                |                                  08 06                                |                                     00 01                                 |                                  08 00                                |                               06                           |                       04                    |                          00 01                           |                                        02 42 AC 1A 00 03                                     |                                       AC 1A 00 03                                           |                                                   00 00 00 00 00 00                                                  |                             AC 1A 00 01                               |
// |------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|

//Detail de la structure sockaddr_ll : 
//struct sockaddr_ll{
//  unsigned short ssl_family (famille d'adresse de la socket normalement toujours AF_PACKET)
//  unsigned short ssl_protocol (Protocol de la couche 2 pour lequel cette adresse s'applique (htons(ETH_P_ALL)))
//  int ssl_ifindex (interface reseau sur laquelle la trame est recu. Pour voir les interfaces et leurs numero sur un systeme on utilise ip link show)
//  unsigned short sll_hatype (Type de matériel associé à l'adresse. Par exemple, pour Ethernet, cela peut être ARPHRD_ETHER)
//  unsigned char sll_pkttype (Type de paquet associé à l'adresse. Il peut s'agir de types de paquets spécifiques tels que PACKET_HOST, PACKET_BROADCAST, PACKET_MULTICAST)
//  unsigned char sll_halen (Longueur de l'adresse mac en octect)
//  unsigned char sll_addr[8] (Tableau contenant l'adresse mac. La taille du tableau est sll_halen)
//}

int main(int argc, char **argv)
{
    if (argc != 5)
        return(printf("Wrong number arguments \n"), 1);
    struct network_frame network_frame_info;
    argv[0] = argv[0];
    char buf[SIZE_MAX_ARP];
    struct sockaddr gen_network_interface;
    socklen_t len = sizeof(gen_network_interface);

    //Pour recuperer toutes les communications qui arrive sur notre machine on utilise des RAW Sockets qui vont permettre de manipuler/composer
    //soi-meme la partie IP du modele OSI. Avec des sockets normal on peut aussi agir sur cette partie mais pas autant on sera plutot sur la partie 4 du modele OSI.
    //On va pouvoir aussi avec ce genre de socket recuperer les requetes broadcast et multicast.
    int sockRaw;

    //Pour creer une RAW socket on donne a socket comme type (2eme arg) SOCK_RAW. Comme domaine (1er arg) AF_PACKET qui va permettre d'accerder au donnes brut
    //incluant les entetes ethernet (couche 2 modele OSI) et IP (couche 3 modele OSI). Ensuite on renseigne le protocol ce sera le type de trame que l'on veut
    //'capturer' il en existe plusieur pour le trame IP, ARP, VLAN et il existe un moyen de tout capturer (ETH_P_ALL) on utilisera ETH_P_ARP pour les trames ARP
    // car il n y'a que celle ci qui nous interesse. Mais typiquement les logiciels de sniffing tel que wireshark utilise ETH_P_ALL. Le kernel a chaque fois
    //qu'il recoit une trame et qu'elle doit aussi aller a notre socket cree un copie de cette trame et l'envoie a la socket.
    //REF (https://stackoverflow.com/questions/62866943/how-does-the-af-packet-socket-work-in-linux et man 7 packet et linux/if_ether.h)
    sockRaw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));

    if (sockRaw < 0)
        return(printf("socket failed : %s\n", strerror(errno)), 1);
    while(1)
    {
        memset(buf, 0, sizeof(buf));

        int recv = recvfrom(sockRaw, buf, SIZE_MAX_ARP, 0, &gen_network_interface, &len);
        if (recv <= 0)
            return (printf("recvfrom failed : %s\n", strerror(errno)), 1);
        /* La structure sockaddr_ll fournit des informations sur l'interface réseau à laquelle une trame a été reçue ou à travers laquelle
        elle sera envoyée. Ces informations sont généralement liées à l'interface réseau locale sur la machine où votre programme s'exécute. */

        network_frame_info.network_interface = (struct sockaddr_ll*)&gen_network_interface;

        /* Ici, nous avons un pointeur 'buf' pointant vers les données brutes de la trame. En effectuant le cast, nous indiquons à 'header_ethernet'
        d'interpréter les données dans 'buf' comme étant une structure de type 'ether_header'. Ainsi, la taille de la structure 'ether_header' correspond
        parfaitement à la taille de l'en-tête Ethernet, permettant à 'header_ethernet' de contenir correctement les informations de l'en-tête.

        Avant d'effectuer le cast, nous effectuons une vérification de taille pour éviter d'éventuelles erreurs. Nous nous assurons que la taille
        du buffer 'recv' est au moins égale à la taille de la structure 'ether_header'. Si ce n'est pas le cas, cela signifierait que les données
        reçues ne sont pas suffisamment longues pour contenir un en-tête Ethernet valide.*/

        if ((size_t)recv < sizeof(struct ether_header))
            return (printf("Cast ether_header impossible"), 1);
        network_frame_info.ethernet_header = (struct ether_header *)buf;

        /* La fonction ntohs() est utilisée pour convertir les entiers de l'ordre des octets du réseau (big-endian) à l'ordre des octets de l'hôte
        (little-endian) en sortie de la trame Ethernet.
        
        Après le cast dans la structure 'ether_header', les valeurs sont stockées en big-endian, ce qui signifie que les octets de poids fort sont
        stockés à l'adresse mémoire la plus basse. Cependant, notre système utilise une représentation little-endian, où les octets de poids 
        faible sont stockés à l'adresse mémoire la plus basse. Par conséquent, pour interpréter correctement le champ 'ether_type' dans la trame Ethernet,
        nous utilisons ntohs() pour convertir les octets de big-endian en little-endian.

        En utilisant ntohs(), nous nous assurons que nous obtenons la valeur correcte du champ 'ether_type', quel que soit l'endianness de notre système, 
        ce qui garantit une interprétation correcte du type de protocole encapsulé dans la trame Ethernet. Je decide de laisser en little-endian
        pour ne pas a avoir a convertir au moment de renvoyer le message*/

        if ((size_t)recv - sizeof(struct ether_header) < sizeof(struct arp_content))
            return (printf("Cast arp_content impossible"), 1);
        network_frame_info.arp_content = (struct arp_content*)(buf + sizeof(struct ether_header));

        printf("-----------------------------------------------\033[1;32mNew ARP Trame recv\033[0m-----------------------------------------------\n");
        print_network_interface(network_frame_info.network_interface);
        print_ethernet_header(network_frame_info.ethernet_header);
        print_arp_content(network_frame_info.arp_content);
        print_trame(buf, (int)recv);
        printf("----------------------------------------------------------------------------------------------------------------\n");
        fflush(stdout);
    }
    return(0);
}