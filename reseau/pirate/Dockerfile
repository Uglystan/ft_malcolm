FROM alpine:latest

RUN apk add --no-cache make
RUN apk add --no-cache build-base linux-headers iputils

COPY ./src/* /

ENTRYPOINT make && ./ft_malcolm 1 2 3 4 > /dev/stdout