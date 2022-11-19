FROM golang:1.19

ARG http_proxy
ARG https_proxy

# Utilities for testing
RUN apt-get update
RUN apt-get install net-tools nmap dnsutils tcpdump iproute2 vim netcat iputils-ping wireguard iperf xsel -y

WORKDIR /wiretap
COPY ./src/go.mod ./src/go.sum ./
RUN go mod download -x

# Build Wiretap
COPY ./src /wiretap

RUN make BIN=.

# Run webserver for testing
CMD python3 -m http.server --bind :: 80
