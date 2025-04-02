FROM debian:bullseye

RUN apt-get update && \
    apt-get install -y make build-essential iputils-ping valgrind procps && \
    apt-get clean

COPY ./src/* /

RUN printf "%s\n" \
"# content of this file will override /etc/sysctl.d/*" \
"net.ipv4.conf.default.send_redirects = 0" \
"net.ipv4.conf.all.accept_redirects = 0" \
"net.ipv4.conf.all.send_redirects = 0" \
"net.ipv4.conf.all.accept_source_route = 0" \
"net.ipv4.ip_forward = 0" \
"net.ipv6.conf.all.forwarding = 0" \
"net.ipv6.conf.all.accept_source_route = 0" \
"net.ipv6.conf.all.accept_redirects = 0" \
"net.ipv4.conf.all.secure_redirects = 0" > /etc/sysctl.conf

RUN make

ENTRYPOINT sysctl -p /etc/sysctl.conf && \
    valgrind --leak-check=full --show-leak-kinds=all ./ft_malcolm 192.168.1.2 02:42:c0:a8:01:02 192.168.1.3 02:42:c0:a8:01:03 -v > /dev/stdout

# ENTRYPOINT sysctl -p /etc/sysctl.conf && make && tail -f /bin/sh
# Se faire passer pour l'ip dans la ligne de commande avec un envoi en broadcast toutes les x secondes + selection d'interface
# ENTRYPOINT sysctl -p /etc/sysctl.conf && make && ./ft_malcolm -g 192.168.1.2 eth0 -v > /dev/stdout

# Verbose mode
# ENTRYPOINT sysctl -p /etc/sysctl.conf && make && ./ft_malcolm 192.168.1.2 02:42:c0:a8:01:02 192.168.1.3 02:42:c0:a8:01:03 -v > /dev/stdout
