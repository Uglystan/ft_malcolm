from scapy.all import Ether, ARP, sendp


# Adresse MAC source personnalisée
source_mac = "9A:2D:C0:98:C3:1E"  # Adresse MAC source que vous souhaitez utiliser

# Adresse MAC de la cible
target_mac = "FF:FF:FF:FF:FF:FF"  # Adresse MAC de broadcast

# Adresse IP de la cible
target_ip = "10.0.2.15"  # Adresse IP de la cible

# Adresse IP source personnalisée
source_ip = "10.0.2.40"  # Adresse IP source personnalisée que vous souhaitez utiliser

interface = "eth1"

# Construction du paquet ARP avec l'adresse IP source personnalisée
arp_packet = Ether(src=source_mac, dst=target_mac) / ARP(op="who-has", pdst=target_ip, psrc=source_ip, hwsrc=source_mac)

# Envoi du paquet ARP
sendp(arp_packet, iface=interface)
