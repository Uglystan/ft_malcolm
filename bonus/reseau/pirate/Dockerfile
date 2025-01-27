FROM alpine:latest

RUN apk add --no-cache make
RUN apk add --no-cache build-base linux-headers iputils

COPY ./src/* /

RUN echo -e "# content of this file will override /etc/sysctl.d/*\n\
net.ipv4.conf.default.send_redirects = 0\n\
net.ipv4.conf.all.accept_redirects = 0\n\
net.ipv4.conf.all.send_redirects = 0\n\
net.ipv4.conf.all.accept_source_route = 0\n\
net.ipv4.ip_forward = 0\n\
net.ipv6.conf.all.forwarding = 0\n\
net.ipv6.conf.all.accept_source_route = 0\n\
net.ipv6.conf.all.accept_redirects = 0\n\
net.ipv4.conf.all.secure_redirects = 0"> /etc/sysctl.conf

# ENTRYPOINT sysctl -p /etc/sysctl.conf && make && tail -f /bin/sh
# Se faire passer pour l'ip dans la ligne de commande avec un envoi en broadcast toutes les x secondes 
# ENTRYPOINT sysctl -p /etc/sysctl.conf && make && ./ft_malcolm -g 192.168.1.2 eth0 -v > /dev/stdout

ENTRYPOINT sysctl -p /etc/sysctl.conf && make && ./ft_malcolm 192.168.1.2 02:42:c0:a8:01:02 192.168.1.3 02:42:c0:a8:01:03 -v > /dev/stdout
