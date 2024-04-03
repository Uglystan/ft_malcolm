FROM debian:buster

RUN apt-get update && \
    apt-get install -y net-tools && \
    apt-get install -y arping && \
    apt-get install -y tcpdump && \
    rm -rf /var/lib/apt/lists/*

CMD ["tcpdump", "-i", "any", "-v", "arp"]