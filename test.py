from scapy.all import *

# Création de la requête ARP
arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="192.168.1.2")

# Envoi de la requête ARP en broadcast
answered, unanswered = srp(arp_request, timeout=2)

# Affichage des réponses
for pkt in answered:
    print(pkt[1].psrc + " - " + pkt[1].hwsrc)
