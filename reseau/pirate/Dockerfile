FROM alpine:latest
RUN apk add --no-cache make
RUN apk add --no-cache build-base linux-headers iputils

COPY ./src/* /

ENTRYPOINT make && ./ft_malcolm 192.168.1.3 02:42:c0:a8:01:03 192.168.1.2 02:42:c0:a8:01:02 > /dev/stdout