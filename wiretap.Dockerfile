FROM golang:1.23

ARG http_proxy
ARG https_proxy

# Utilities for testing
RUN apt-get update
RUN apt-get install net-tools nmap dnsutils tcpdump iproute2 vim netcat-openbsd iputils-ping wireguard iperf xsel masscan nano less tcpdump socat ca-certificates -y

# Support custom CA cert files for Internet access; required by for go commands to work in some environments
# The * prevents failure if the file doesn't exist
COPY trusted-ca*.crt /usr/local/share/ca-certificates/
RUN update-ca-certificates

WORKDIR /wiretap
COPY ./src/go.mod ./src/go.sum ./
RUN go mod download -x

# Build Wiretap
COPY ./src /wiretap

RUN make OUTPUT=./wiretap

# Run webserver for testing
CMD python3 -m http.server --bind :: 80
