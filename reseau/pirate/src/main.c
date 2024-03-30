#include "main.h"

//Detaille d'une trame arp (hexadecimal) taille max 1500 octects (a la fin possible padding (0000000000)):
// |----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
// |                                                                      Entete ethernet                                                                                    |                                                                                                                                                                                                                                                                                                                                               Entete ARP                                                                                                                                                                                                                                                                                                                       |
// |----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
// | Adresse MAC de Destination du paquet (6 octect) | Adresse MAC de l'emetteur du paquet (6 octect) | Type de protocole encapsule dans la trame (2 octects) (Pour arp 0806) | Type d'operation (2 octects) (0001 pour request ARP et 0002 pour reponse) | Type de protocole reseau en general IPv4 (2 octects) (0800 pour IPv4) |  Longueur adresse MAC en octect (1 octect) (en general 06) | Longueur adresse IP en octect (1 octect 04) | Opcode (2 octects) | Adresse MAC de l'émetteur de la requête ou de la réponse (6 octect en focntion de precedent) | Adresse IP de l'émetteur de la requête ou de la réponse (4 octect en focntion de precedent) | Adresse MAC du destinataire de la requête ou de la réponse Inconnue et remplie de zéros dans une requête (6 octects) | Adresse IP du destinataire de la requête ou de la réponse (4 octects) |
// |----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
// |                FF FF FF FF FF FF                |               02 42 AC 1A 00 03                |                                  08 06                                |                                     00 01                                 |                                  08 00                                |                               06                           |                       04                    |       00 01        |                                        02 42 AC 1A 00 03                                     |                                       AC 1A 00 03                                           |                                                   00 00 00 00 00 00                                                  |                             AC 1A 00 01                               |
// |----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|

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

// Transform data en binaire
//Je met le bit en position la plus faible et je le compare avec 1 donc je l'extrait et ensuite je le met dans une string d'ou le +48
// Dans cette fonction je vais extraire bit par bit ce que j'ai recu dans recvfrom donc je decale le chaque bit de chaque octect pour le mettre en position la plus faible
// Et ensuite avec le AND 1 je l'extrait et comme je le met dans une chaine de caractere je fais +48
void converToBinary(char *data, int length) {
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

void binaryToHex(char *binStr) {
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

int main(int argc, char **argv)
{
    if (argc != 5)
    {
        return(printf("Wrong number arguments \n"), 1);
        return (1);
    }
    argv[0] = argv[0];
    char buf[SIZE_MAX_ARP];
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
    sockRaw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));

    printf("%d\n", sockRaw);
    if (sockRaw < 0)
    {
        printf("socket failed : %s\n", strerror(errno));
        return(1);
    }
    while(1)
    {
        memset(buf, 0, sizeof(buf));
        //On utilise recvfrom qui est comme recv mais avec pour particulariter de remplir la structure addr avec les informations de l'expediteur du message
        //recu ca sera utile pour la suite pour envoyer un message a l'expediteur.
        //sockaddr est concu pour gerer different type de socket donc c'est une structure generique alors que sockaddr_ll est specifique au adresse de niveau 2
        //(Couche liaison du modele OSI) et fonctionne specifiquement avec AF_PACKET comme recvfrom est une focntion qui doit pouvoir marcher avec different type
        //Elle prend comme argument sockaddr. Mais ensuite si on est sur d'utiliser AF_PACKET on pourra converti/caster sockaddr en sockaddr_ll et dans sockaddr_ll
        //On a enfaite les information ethernet et dans la trame les informations IP
        int recv = recvfrom(sockRaw, buf, SIZE_MAX_ARP, 0, &addr, &len);
        if (recv <= 0)
        {
            printf("recvfrom failed : %s\n", strerror(errno));
            return (1);
        }
        addr_ll = convert_to_sockaddr_ll(addr);
        print_addr_ll(addr_ll);
        printf("Data : ");
        converToBinary(buf, recv);
        binaryToHex(buf);
        printf("%s\n", buf);
        printf("\n");
        printf("\n");
        fflush(stdout);
        memset(buf, 0, sizeof(buf));
    }
    return(0);
}