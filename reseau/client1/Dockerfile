FROM alpine:latest

RUN apk add --no-cache iputils

RUN echo -e "# content of this file will override /etc/sysctl.d/*\n\
net.ipv4.conf.all.accept_redirects = 1\n\
net.ipv4.conf.all.arp_accept = 1" > /etc/sysctl.conf

ENTRYPOINT sysctl -p /etc/sysctl.conf && tail -f /bin/sh