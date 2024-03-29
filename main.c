#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <ifaddrs.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <string.h>
#include <errno.h>
#include <netpacket/packet.h>
#include <net/if_arp.h>
#include <netinet/ether.h>

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
struct sockaddr_ll convert_to_sockaddr_ll(const struct sockaddr addr)
{
    struct sockaddr_ll addr_ll;
    addr_ll = *(struct sockaddr_ll*)&addr;
    return (addr_ll);
}


void print_addr_ll(const struct sockaddr_ll sll)
{
        printf("sll_family : %s\n", (sll.sll_family == AF_PACKET) ? "AF_PACKET" : "AUTRES" );
        printf("sll_protocol : %s\n", (htons(sll.sll_protocol) == ETH_P_ARP) ? "ARP" : "AUTRES");
        printf("sll_ifindex : %d\n", sll.sll_ifindex);
        printf("sll_hatype : %s\n", (sll.sll_hatype == ARPHRD_ETHER) ? "Adresse Ethernet" : (sll.sll_hatype == ARPHRD_IEEE80211) ? "Adresse WiFI" : (sll.sll_hatype == ARPHRD_LOOPBACK) ? "Interface LoopBack" : "");
        printf("sll_pktype Packet %s\n", (sll.sll_pkttype == PACKET_HOST) ? "pour : hote local" : (sll.sll_pkttype == PACKET_BROADCAST) ? " pour : broadcast" : (sll.sll_pkttype == PACKET_MULTICAST) ? "pour : multicast" : (sll.sll_pkttype == PACKET_OTHERHOST) ? "pour : autre interface sur reseau local" : (sll.sll_pkttype == PACKET_OUTGOING) ? "envoye par hote local" : "");
        printf("sll_halen (Taille adresse MAC en octect): %d octect\n", sll.sll_halen);
        printf("sll_addr (Adresse MAC): %s\n", ether_ntoa((struct ether_addr *)sll.sll_addr));
}


int main(int argc, char **argv)
{
    if (argc != 5)
    {
        return(printf("Wrong number arguments \n"), 1);
        return (1);
    }
    argv[0] = argv[0];
    char buf[100000];
    struct sockaddr addr;
    struct sockaddr_ll addr_ll;
    socklen_t len = sizeof(addr);

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
    sockRaw = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));

    printf("%d\n", sockRaw);
    if (sockRaw < 0)
    {
        printf("socket failed : %s\n", strerror(errno));
        return(1);
    }
    while(1)
    {
        //On utilise recvfrom qui est comme recv mais avec pour particulariter de remplir la structure addr avec les informations de l'expediteur du message
        //recu ca sera utile pour la suite pour envoyer un message a l'expediteur.
        //sockaddr est concu pour gerer different type de socket donc c'est une structure generique alors que sockaddr_ll et specifique au adresse de niveau 2
        //(Couche liaison du modele OSI) et fonctionne specifiquement avec AF_PACKET comme recvfrom est une focntion qui doit pouvoir marcher avec different type
        //Elle prend comme argument sockaddr. Mais ensuite si on est sur d'utiliser AF_PACKET on pourra converti/caster sockaddr en sockaddr_ll
        int recv = recvfrom(sockRaw, buf, 100000, 0, &addr, &len);
        if (recv <= 0)
        {
            printf("recvfrom failed : %s\n", strerror(errno));
            return (1);
        }
        addr_ll = convert_to_sockaddr_ll(addr);
        print_addr_ll(addr_ll);
        printf("Data : ");
        for (int i = 0; i <= recv; i++)
        {
            printf("%02X ", buf[i]);
        }
        printf("\n");
        printf("\n");
        // printf("addr.sa_data = %s\n", addr.sa_data);
        // printf("addr.sa_family = %s\n", (addr.sa_family == AF_PACKET) ? " (AF_PACKET)" : (addr.sa_family == AF_INET) ? " (AF_INET)" : (addr.sa_family == AF_INET6) ? " (AF_INET6)" : "");
        // printf("Buf = %s\n", buf);
        // printf("Size buf = %ld\n", strlen(buf));
        memset(buf, 0, sizeof(buf));
    }
    return(0);
}
    // struct ifaddrs *test, *temp;
    // int family, s;
    // int err = getifaddrs(&test);
    // char host[NI_MAXHOST];
    // if (err == -1)
    //     printf("Error getifaddr\n");
    // int i = 0;
    // temp = test;
    // while(temp->ifa_next != NULL)
    // {
    //     printf("Element de liste %d\n", i);
    //     if (temp->ifa_addr == NULL)
    //     {
    //         printf("addr NULL");
    //         continue;
    //     }
    //     family = temp->ifa_addr->sa_family;
    //     printf("%s\t adresse family: %d%s\n", temp->ifa_name, family, (family == AF_PACKET) ? " (AF_PACKET)" : (family == AF_INET) ? " (AF_INET)" : (family == AF_INET6) ? " (AF_INET6)" : "");
    //     if (family == AF_INET6 || family == AF_INET)
    //     {
    //         s = getnameinfo(temp->ifa_addr, (family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6), host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
    //         if (s != 0)
    //         {
    //             printf("Error getnameinfo\n");
    //         }
    //         printf("\taddresse: <%s>\n", host);
    //     }
    //     printf("\n");
    //     temp = temp->ifa_next;
    //     i++;
    // }
    // freeifaddrs(test);