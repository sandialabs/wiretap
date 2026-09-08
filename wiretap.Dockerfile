FROM golang:1
ENV GOTOOLCHAIN=auto

ARG http_proxy
ARG https_proxy

# Utilities for testing
RUN apt-get update
RUN apt-get install net-tools nmap dnsutils tcpdump iproute2 vim netcat-openbsd iputils-ping wireguard iperf xsel nano less tcpdump socat -y

WORKDIR /wiretap
COPY ./src/go.mod ./src/go.sum ./
RUN go mod download -x

# Build Wiretap
COPY ./src /wiretap

RUN make OUTPUT=./wiretap

# Run webserver for testing
CMD python3 -m http.server --bind :: 80
