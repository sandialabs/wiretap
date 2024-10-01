<div align="center">

# <img align="center" src="media/wiretap_logo.png" width="20%"> Wiretap

Wiretap is a transparent, VPN-like proxy server that tunnels traffic via WireGuard and requires no special privileges to run.
</div>

In this diagram, the Client has generated and installed WireGuard configuration files that will route traffic destined for `10.0.0.0/24` through a WireGuard interface. Wiretap is then deployed to the Server with a configuration that connects to the Client as a WireGuard peer. The client can then interact with resources local to the Server as if on the same network, and optionally chain additional servers to reach new networks. Access to the Wiretap network can also be shared with other Clients.

<div align="center">

![Wiretap Diagram](media/Wiretap_Animated.svg)
</div>

# Terminology and Requirements

A Wiretap Server is any machine where a Wiretap binary is running the `serve` subcommand. Servers generate and receive network traffic on behalf of Wiretap Clients, acting like a VPN "exit node."

A Wiretap Client is any machine running the Wireguard configurations necessary to send network traffic through a Wiretap Server. It functions much like a client in a VPN connection.

> [!IMPORTANT]
> Unlike the typical use of "client" and "server" terms in networking, Wiretap's Client and Server terms have nothing to do with which machine listens for or initiates the initial connection.

## Client System Requirements

* WireGuard - https://www.wireguard.com/install/
* Privileged access necessary to configure WireGuard


## Server System Requirements

* Ability to get the Wiretap binary onto the Server system, and run it


## Environment Requirements

* Bidirectional UDP communication between Server and Client on one port. Any firewalls between them must allow at least one machine to initiate the UDP connection to the other.
    * The machine receiving the initial connection (the Client by default) must be able to listen for UDP connections on a port that the initiating machine can connect to.

> [!NOTE]
> By default the Server initiates the handshake to the Client because the Server is more likely to have outbound UDP allowed through a firewall than inbound UDP, but the reverse is easily configurable.

While not ideal, Wiretap can still work with TCP instead of UDP. See the experimental [TCP Tunneling](#tcp-tunneling) section for more info.

# Quick Start

1. Download binaries from the [releases](https://github.com/sandialabs/wiretap/releases) page, one for your Client machine and one for your Server machine (if different os/arch). Copy the Wiretap binary onto the server
2. On the Client, run `./wiretap configure --endpoint <IP>:<port> --routes <CIDRs>` with the appropriate arguments
3. Copy the server command output that best suits the Server OS and run it on the Server machine
4. On the Client, run `sudo wg-quick up ./wiretap_relay.conf && sudo wg-quick up ./wiretap.conf` to import the configs into Wireguard
5. Confirm the handshake completed for both configs by running `sudo wg show` on the Client
6. (Optional) Add more servers and clients as needed with the `wiretap add` subcommand

See the [Usage section](#Usage) for more details.

# Installation

No installation of Wiretap is required. Just grab a binary from the [releases](https://github.com/sandialabs/wiretap/releases) page. You may need two different binaries if the OS/ARCH are different on the client and server machines.

If you want to compile it yourself or can't find the OS/ARCH you're looking for, install Go (>=1.20) from https://go.dev/dl/ and use the provided [Makefile](./src/Makefile).

# How it Works

Feel free to skip this section, but understanding how Wiretap works at a high level is very helpful for troubleshooting when you run into issues or errors. Additionally, some of the documentation below assumes you've read this.

> [!NOTE]
> This section is intended to provide an intuitive, working understanding of how Wiretap works, and may not be entirely technically accurate about implementation details.


Client-to-Server and Server-to-Server connections are established using a `relay` Wireguard tunnel (`wiretap_relay.conf`). These UDP connections occur over real-world TCP/IP network infrastructure. Each relay tunnel connects one Wiretap instance (Server or Client) directly to one other instance. They become Wireguard peers, able to pass encrypted messages back and forth between each other. When a new Server or Client is added to the Wiretap network, it is attached to an existing Server by creating a new relay tunnel between them.

Inside the relay tunnels, Wiretap establishes a second virtual End-to-End Encrypted (`EE2E`) network (`wiretap.conf`). This network is invisible to the real-world network. Each Server and Client gets its own unique internal IP addresses inside this network: `172.X.X.X` for IPv4, and `fd:XX::X` for IPv6. As the EE2E name suggests, each Client-Server pair within this virtual network become Wireguard peers, able to generate encrypted messages that only the other can decrypt.

Wiretap Clients track which real-world IP ranges ("routes") have been assigned to each Server inside the relay network. When the Client machine generates a packet destined for a known Wiretap route, Wireguard encrypts it using the EE2E configuration associated with the Server assigned to that route. The encrypted packet (now a UDP datagram) gets marked with the E2EE IP address of the assigned server as its destination.

At this point, the Client may not have a direct relay connection to the destination Server, so the chain of Servers within the relay network act much like standard TCP/IP routers. The Client passes the datagram to the first Server through their relay tunnel, adding a layer of relay encryption that only that Server can decrypt. The Server receives the datagram, decrypts the relay encryption, identifies which of its peer servers in the relay network the EE2E datagram should be sent to next, and sends it off via the associated relay tunnel.

The process repeats until the packet reaches the intended Wiretap Server. That Server is finally able to decrypt the E2EE encryption (using its E2EE peer configuration for the Client), revealing the original packet data. It sends the packet to the real-world IP address indicated in the packet header, and forwards any response packets back to the Client using the same process.

Within the E2EE network (i.e., accessible only to Clients), Wiretap Servers expose an API to enable real-time configuration changes and to monitor the health of the Wiretap network. Each Server is assigned an additional unique IP (usually an IPv6 address) inside the E2EE network to enable the secure usage of this API. This IP is referred to as the "API address."

# Usage

Wiretap provides the following subcommands, which are documented in this section:
* [configure](#Configure)
* [serve](#Serve)
* [add server](#Add-Server-(Optional))
* [add client](#Add-Client-(Optional))
* [expose](#Expose-(Port-Forwarding))

Get help for any subcommand by adding the `-h` flag to it.

> [!TIP]
> Some deprecated and less-common flags are hidden from the standard help output. Add the `-H` flag as well to see them.

## Configure

<div align="center">

![Wiretap Configure Arguments](media/Wiretap_Configure.svg)
</div>

On the Client machine, run Wiretap's `configure` subcommand to generate starting config files:

```bash
./wiretap configure --endpoint <IP>:<port> --routes <CIDRs>
```

* `--endpoint` tells the Server machine how to connect to the Client machine's Relay interface (the E2EE interfaces already know how to talk to each other if the Relay interfaces are working)
* `--routes` is the equivalent of WireGuard's `AllowedIPs` setting. This tells the Client to route traffic that matches these IP ranges through Wiretap.

> [!IMPORTANT]
> By default the listening port will be configured to be the same as the port specified in the `--endpoint` IP:port. This can be overwritten using the `--port` argument.

Following the example in the diagram:
```bash
./wiretap configure --endpoint 1.3.3.7:1337 --routes 10.0.0.0/24
```

---

<details>

<summary>Click to view output</summary>

```
Configurations successfully generated.
Import the two configs into WireGuard locally and pass the arguments below to Wiretap on the remote machine.

config: wiretap_relay.conf
────────────────────────────────
[Interface]
PrivateKey = cGsJkcVIajZW7kfN5SMwijmMx59ke7FZ+qdZOcsNDE0=
Address = 172.16.0.1/32
Address = fd:16::1/128
ListenPort = 1337

[Peer]
PublicKey = kMj7HwfYYFO/XEHNFK2kz9cBd7vTHk63fhygyuYLMzI=
AllowedIPs = 172.17.0.0/24,fd:17::/48
────────────────────────────────

config: wiretap.conf
────────────────────────────────
[Interface]
PrivateKey = YCTRVwB4xOEcBtifVmhjMhRYL7+DOlDP5VdHZGclZGg=
Address = 172.19.0.1/32
Address = fd:19::1/128
ListenPort = 51821
MTU = 1340

[Peer]
PublicKey = 3ipWthpJzqVo5wcb1TSDS1M8YOiBQYBPmbj3mVD/5Fg=
AllowedIPs = 10.0.0.0/24,::2/128
Endpoint = 172.17.0.2:51821
────────────────────────────────

server config: wiretap_server.conf

server command:
POSIX Shell:  WIRETAP_RELAY_INTERFACE_PRIVATEKEY=WDH8F6rSUZDyQFfEsRjWLCnapU254qrSAfpGyGs+N1Y= WIRETAP_RELAY_INTERFACE_PORT=51820 WIRETAP_RELAY_PEER_PUBLICKEY=Ta75SvIb2v2V8EDo6oE2Fvsys/CNlkzW+aPjxdY+Dlc= WIRETAP_RELAY_PEER_ENDPOINT=1.3.3.7:1337 WIRETAP_E2EE_INTERFACE_PRIVATEKEY=GKzGBe3qS7JuLp0vMAErBW6lAewvmFowCIbcgwzComg= WIRETAP_E2EE_PEER_PUBLICKEY=cXddDGWCzd5igux4FDv97XBsyLH0SRPehhTz3E2IXBM= WIRETAP_E2EE_PEER_ENDPOINT=172.16.0.1:51821 ./wiretap serve
 PowerShell:  $env:WIRETAP_RELAY_INTERFACE_PRIVATEKEY="WDH8F6rSUZDyQFfEsRjWLCnapU254qrSAfpGyGs+N1Y="; $env:WIRETAP_RELAY_INTERFACE_PORT="51820"; $env:WIRETAP_RELAY_PEER_PUBLICKEY="Ta75SvIb2v2V8EDo6oE2Fvsys/CNlkzW+aPjxdY+Dlc="; $env:WIRETAP_RELAY_PEER_ENDPOINT="1.3.3.7:1337"; $env:WIRETAP_E2EE_INTERFACE_PRIVATEKEY="GKzGBe3qS7JuLp0vMAErBW6lAewvmFowCIbcgwzComg="; $env:WIRETAP_E2EE_PEER_PUBLICKEY="cXddDGWCzd5igux4FDv97XBsyLH0SRPehhTz3E2IXBM="; $env:WIRETAP_E2EE_PEER_ENDPOINT="172.16.0.1:51821"; .\wiretap.exe serve
Config File:  ./wiretap serve -f wiretap_server.conf
```
</details>

---

> [!NOTE]
> The 51821 ListenPort in `wiretap.conf` needs to be available for use on the Client, but does NOT need to be accessible to the Server over real-world networks. See the [How It Works](#how-it-works) section for details. Use `--simple` in both the `config` command and the Server's `serve` command if your setup requires a single interface on the Client

Install the resulting `wiretap_relay.conf` and `wiretap.conf` configs files into WireGuard on the Client:

* If using a GUI, select the menu option similar to *Import Tunnel(s) From File*
* If you have `wg-quick` installed, run `sudo wg-quick up ./wiretap_relay.conf && sudo wg-quick up ./wiretap.conf`

> [!TIP]
> You can modify the AllowedIPs in the `wiretap.conf` file any time after generating the config files, just reload the config file with `wg-quick down ./wiretap.conf && wg-quick up ./wiretap.conf` after making the change. No changes are needed on the server to update them.

> [!WARNING]
> In the default configuration, with the Client listening for an initial Server connection, the Server will still also listen on port 51820 so that other Servers can attach to it later. There is currently no way to change this when running the `configure` command, but when running `wiretap serve` you can manually change this in the `wiretap_server.conf` file, or using the `WIRETAP_RELAY_INTERFACE_PORT` environment variable.

Don't forget to disable or remove the tunnels when you're done (e.g., `sudo wg-quick down ./wiretap.conf && sudo wg-quick down ./wiretap_relay.conf`)

## Serve

On the remote machine, upload the Wiretap binary and then run one of the commands from the output of `configure` to start Wiretap in server mode:
```powershell
$env:WIRETAP_RELAY_INTERFACE_PRIVATEKEY="WDH8F6rSUZDyQFfEsRjWLCnapU254qrSAfpGyGs+N1Y="; $env:WIRETAP_RELAY_INTERFACE_PORT="51820"; $env:WIRETAP_RELAY_PEER_PUBLICKEY="Ta75SvIb2v2V8EDo6oE2Fvsys/CNlkzW+aPjxdY+Dlc="; $env:WIRETAP_RELAY_PEER_ENDPOINT="1.3.3.7:1337"; $env:WIRETAP_E2EE_INTERFACE_PRIVATEKEY="GKzGBe3qS7JuLp0vMAErBW6lAewvmFowCIbcgwzComg="; $env:WIRETAP_E2EE_PEER_PUBLICKEY="cXddDGWCzd5igux4FDv97XBsyLH0SRPehhTz3E2IXBM="; $env:WIRETAP_E2EE_PEER_ENDPOINT="172.16.0.1:51821"; .\wiretap.exe serve
```

There are two other ways to pass arguments to the server:
1. With the generated server config file: `-f wiretap_server.conf`
2. The legacy method of passing command line arguments (`--endpoint 1.3.3.7:1337 ...`). Be aware that this method exposes the arguments to other users on the system. A compromised private key can be used to connect to the client as a peer and/or decrypt traffic

> [!NOTE]
> The wiretap_server.conf file uses a notation unique to Wiretap. It cannot be used to start a server with `wg-quick` or other generic Wireguard tools.

Confirm that the relay interfaces on the Client and Server have successfully completed a handshake. The Client should see successful handshakes in whatever WireGuard interface is running. If using the command-line tools, check with `sudo wg show`. By default the E2EE handshake will not occur until the Client sends data, so you may need to attempt to use the connection (e.g. `ping` an IP in the associated `--routes`) to trigger the handshake process.

Now the Client should be able to interact with the `routes` specified in the `configure` command!

## Add Server (Optional)

<div align="center">

![Wiretap Add Server Arguments](media/Wiretap_Add_Server.svg)
</div>

The `add server` subcommand is meant to extend the Wiretap network to reach new areas of a target network. At least one Client and Server must be configured and successfully deployed (i.e., with `configure`) before adding another Server. Servers can attach to any other Server *or* the Client itself.

> [!WARNING]
> Due to the way new Clients are added to existing networks, all Servers must be deployed *before* adding additional Clients. Added Clients won't be able to access Servers deployed after they were added. Additionally, if a Wiretap Server process exits or dies for any reason it will not remember any added Clients when you restart it.

You can view the state of the network and see API addresses with `./wiretap status`

```bash
./wiretap status
```
```
╭────────────────────────╮
│ Wiretap Network Status │
╰────────────┬───────────╯
             │
  ╭──────────┴──────────╮
  │client               │
  │                     │
  │  relay: Ta75SvIb... │
  │   e2ee: cXddDGWC... │
  │                     │
  ╰──────────┬──────────╯
             │
  ╭──────────┴──────────╮
  │server               │
  │  relay: kMj7HwfY... │
  │   e2ee: 3ipWthpJ... │
  │                     │
  │    api: ::2         │
  │ routes: 10.0.0.0/24 │
  ╰─────────────────────╯
```

If you plan to attach a Server directly to the Client, the status command just confirms that everything is working as expected and the network layout is correct. If you want to attach a new Server to an existing Server you must also specify the existing Server's API address in your `add server` command using the `--server-address` argument; this API address **must** reference the same existing Server that the new Server will connect to via the `--endpoint` IP:port or else the new connection will fail.

In this example, we will to the server with API address `::2`, which is listening on `10.0.0.2:51820`. This command will generate a configuration you can deploy to the new Server (through environment variables or a config file), just like with the `configure` command:

```bash
./wiretap add server --server-address ::2 --endpoint 10.0.0.2:51820 --routes 10.0.1.0/24
```
```
Configurations successfully generated.
Import the updated config(s) into WireGuard locally and pass the arguments below to Wiretap on the new remote server.

config: wiretap.conf
────────────────────────────────
[Interface]
PrivateKey = YCTRVwB4xOEcBtifVmhjMhRYL7+DOlDP5VdHZGclZGg=
Address = 172.19.0.1/32
Address = fd:19::1/128
ListenPort = 51821
MTU = 1340

[Peer]
PublicKey = 3ipWthpJzqVo5wcb1TSDS1M8YOiBQYBPmbj3mVD/5Fg=
AllowedIPs = 10.0.0.0/24,::2/128
Endpoint = 172.17.0.2:51821

[Peer]
PublicKey = YOVI9nOvjOWTre0OVzrjx8qsYRgyuSLWndv28S2udiQ=
AllowedIPs = 10.0.1.0/24,::3/128
Endpoint = 172.17.0.3:51821
────────────────────────────────

server config: wiretap_server_1.conf

POSIX Shell:  WIRETAP_RELAY_INTERFACE_PRIVATEKEY=sLERnxT2+VdwwcJOTUHK5fa5sIN7oJ1Jww9n42txrEQ= WIRETAP_RELAY_INTERFACE_PORT=51820 WIRETAP_RELAY_INTERFACE_IPV4=172.17.0.3 WIRETAP_RELAY_INTERFACE_IPV6=fd:17::3 WIRETAP_RELAY_PEER_PUBLICKEY=kMj7HwfYYFO/XEHNFK2kz9cBd7vTHk63fhygyuYLMzI= WIRETAP_RELAY_PEER_ALLOWED=172.16.0.0/16,fd:16::/40 WIRETAP_RELAY_PEER_ENDPOINT=10.0.0.2:51820 WIRETAP_E2EE_INTERFACE_PRIVATEKEY=uF79x5X8q3Vd/ajWMR5XyDt/haahtpy5PkJj9b+OaUE= WIRETAP_E2EE_INTERFACE_API=::3 WIRETAP_E2EE_PEER_PUBLICKEY=cXddDGWCzd5igux4FDv97XBsyLH0SRPehhTz3E2IXBM= WIRETAP_E2EE_PEER_ENDPOINT=172.16.0.1:51821 ./wiretap serve
 PowerShell:  $env:WIRETAP_RELAY_INTERFACE_PRIVATEKEY="sLERnxT2+VdwwcJOTUHK5fa5sIN7oJ1Jww9n42txrEQ="; $env:WIRETAP_RELAY_INTERFACE_PORT="51820"; $env:WIRETAP_RELAY_INTERFACE_IPV4="172.17.0.3"; $env:WIRETAP_RELAY_INTERFACE_IPV6="fd:17::3"; $env:WIRETAP_RELAY_PEER_PUBLICKEY="kMj7HwfYYFO/XEHNFK2kz9cBd7vTHk63fhygyuYLMzI="; $env:WIRETAP_RELAY_PEER_ALLOWED="172.16.0.0/16,fd:16::/40"; $env:WIRETAP_RELAY_PEER_ENDPOINT="10.0.0.2:51820"; $env:WIRETAP_E2EE_INTERFACE_PRIVATEKEY="uF79x5X8q3Vd/ajWMR5XyDt/haahtpy5PkJj9b+OaUE="; $env:WIRETAP_E2EE_INTERFACE_API="::3"; $env:WIRETAP_E2EE_PEER_PUBLICKEY="cXddDGWCzd5igux4FDv97XBsyLH0SRPehhTz3E2IXBM="; $env:WIRETAP_E2EE_PEER_ENDPOINT="172.16.0.1:51821"; .\wiretap.exe serve
Config File:  ./wiretap serve -f wiretap_server_1.conf
```

The Client's E2EE configuration (`wiretap.conf`) will be modified to allow communication with the new Server, so you need to reimport it. For example, `sudo wg-quick down ./wiretap.conf && sudo wg-quick up ./wiretap.conf`. If you are attaching a new Server directly to the Client, the Relay interface will also need to be refreshed in the same way.

Now you can use any of the `serve` command options to start Wiretap on the new Server. It will then join the Wiretap network by connecting to the existing Server.

At this point the new routes should be usable! You can confirm that everything looks correct with `wiretap status`:

```bash
./wiretap status
```
```
╭────────────────────────╮
│ Wiretap Network Status │
╰────────────┬───────────╯
             │
  ╭──────────┴──────────╮
  │client               │
  │                     │
  │  relay: Ta75SvIb... │
  │   e2ee: cXddDGWC... │
  │                     │
  ╰──────────┬──────────╯
             │
  ╭──────────┴──────────╮
  │server               │
  │  relay: kMj7HwfY... │
  │   e2ee: 3ipWthpJ... │
  │                     │
  │    api: ::2         │
  │ routes: 10.0.0.0/24 │
  ╰──────────┬──────────╯
             │
  ╭──────────┴──────────╮
  │server               │
  │  relay: GMkUzfDy... │
  │   e2ee: YOVI9nOv... │
  │                     │
  │    api: ::3         │
  │ routes: 10.0.1.0/24 │
  ╰─────────────────────╯
```

Now the Client can reach `10.0.0.0/24` and `10.0.1.0/24`. From here you can attach more Servers to any of the three existing nodes.

## Add Client (Optional)

<div align="center">

![Wiretap Add Client Arguments](media/Wiretap_Add_Client.svg)
</div>

The `add client` subcommand can be used to share access to the Wiretap network with others.

> [!WARNING]
> All servers must be deployed *before* adding additional clients. Additionally, if a Wiretap Server process exits or dies for any reason it will not remember any added Clients when you restart it.

Adding a new Client is very similar to the other commands. It will generate a `wiretap.conf` and `wiretap_relay.conf` for sharing. Make sure that all of the first-hop Servers (any Server directly attached to the original Client) can reach or be reached by the new Client or else the new Client won't have access to that chain of Servers. Once you get the endpoint information from whoever will be running the new Client (the IP and port they will listen on), run:

```bash
./wiretap add client --endpoint 1.3.3.8:1337 --port 1337
```
```
Configurations successfully generated.
Have a friend import these files into WireGuard

config: wiretap_relay_1.conf
────────────────────────────────
[Interface]
PrivateKey = UEgzp6zv8lNnpih31RfzKsz+BLyN5qNfh6PbCdF1Cmg=
Address = 172.16.0.2/32
Address = fd:16::2/128
ListenPort = 1337

[Peer]
PublicKey = kMj7HwfYYFO/XEHNFK2kz9cBd7vTHk63fhygyuYLMzI=
AllowedIPs = 172.17.0.0/24,fd:17::/48
────────────────────────────────

config: wiretap_1.conf
────────────────────────────────
[Interface]
PrivateKey = 8AhL1kDjwBn/IoY4KLd5mMP4GQsyMYNsqYm3aM/bHnE=
Address = 172.19.0.2/32
Address = fd:19::2/128
ListenPort = 51821
MTU = 1340

[Peer]
PublicKey = 3ipWthpJzqVo5wcb1TSDS1M8YOiBQYBPmbj3mVD/5Fg=
AllowedIPs = 10.0.0.0/24,::2/128
Endpoint = 172.17.0.2:51821

[Peer]
PublicKey = YOVI9nOvjOWTre0OVzrjx8qsYRgyuSLWndv28S2udiQ=
AllowedIPs = 10.0.1.0/24,::3/128
Endpoint = 172.17.0.3:51821
────────────────────────────────
```

Send these files and have the recipient import them into WireGuard to have access to everything in the Wiretap network! By default the routes (AllowedIPs) are copied over to the new client configs, but can be modified by the recipient as needed.

## Expose (Port Forwarding)

> **Warning**
> Port forwarding exposes ports and services on your local machine to the remote network, use with caution

You can expose a port on the Client to IPs in Wiretap's `routes` list by using the `expose` subcommand. For example, to allow remote systems to access port 80/tcp on your local Client machine, you could run:

```
./wiretap expose --local 80 --remote 8080
```

Now all Wiretap Servers will be bound to listen on port 8080/tcp and proxy connections to your service on port 80/tcp. By default this uses IPv6, so make sure any exposed services listening on the Client support IPv6 as well.

To configure Wiretap to only use IPv4, use the `configure` subcommand's `--disable-ipv6` option.

> [!WARNING]
> If a Wiretap server process exits or dies for any reason it will not remember ports it was previously exposing. You will need to re-expose any ports you configured with this command.

To dynamically expose all ports on the Client using SOCKS5:

```
./wiretap expose --dynamic --remote 8080
```

All servers will spin up a SOCKS5 server on port 8080 and proxy traffic to your local machine and can be used like this:

```
curl -x socks5://<server-ip>:8080 http://<any-ip>:1337
```

The destination IP will be rewritten by the server so you can put any address.

### List

Use `./wiretap expose list` to see all forwarding rules currently configured.

### Remove

Use `./wiretap expose remove` with the same arguments used in `expose` to delete a rule. For example, to remove the SOCKS5 example above:

```
./wiretap expose remove --dynamic --remote 8080
```

# How It Works

A traditional VPN can't be installed by unprivileged users because VPNs rely on dangerous operations like changing network routes and working with raw packets.

Wiretap bypasses this requirement by rerouting traffic to a user-space TCP/IP network stack, where a listener accepts connections on behalf of the true destination. Then it creates a new connection to the true destination and copies data between the endpoint and the peer. This is similar to how https://github.com/sshuttle/sshuttle and https://github.com/nicocha30/ligolo-ng work, but relies on WireGuard as the tunneling mechanism rather than SSH or TLS.

To build secure and scalable tunnels across multiple hops, each node in the Wiretap network has two interfaces: Relay and E2EE (end-to-end encrypted). The Relay nodes simply *relay* packets between nodes, but cannot see the plaintext. When a Relay node sees a packet that does not match routing rules, it forwards it to its own E2EE interface where contents can be decrypted by only that interface. There are two layers of WireGuard encapsulation between any two nodes.

<div align="center">

![Wiretap E2EE Architecture](media/Wiretap_E2EE.svg)
</div>

# Help

```bash
./wiretap --help --show-hidden
```
```
Usage:
  wiretap [flags]
  wiretap [command]

Available Commands:
  add         Add peer to wiretap
  configure   Build wireguard config
  expose      Expose local services to servers
  help        Help about any command
  ping        Ping wiretap server API
  serve       Listen and proxy traffic into target network
  status      Show peer layout

Flags:
  -h, --help          help for wiretap
  -H, --show-hidden   show hidden flag options
  -v, --version       version for wiretap

Use "wiretap [command] --help" for more information about a command.
```

# Features

* Network
    - IPv4
    - IPv6
    - ICMPv4: Echo requests and replies
    - ICMPv6: Echo requests and replies
* Transport
    - TCP
        - Transparent connections
        - RST response when port is unreachable
        - Reverse Port Forward
        - Reverse Socks5 Support
    - UDP
        - Transparent "connections"
        - ICMP Destination Unreachable when port is unreachable
        - Reverse Port Forward
* Application
    - API internal to Wiretap for dynamic configuration
    - Chain servers together to tunnel traffic through an arbitrary number of machines
    - Add clients after deployment for multi-user support

# Demo

Please see the [Demo page in the Wiki](https://github.com/sandialabs/wiretap/wiki/Demo) for instructions on setting up the demo Docker environment.

> [!TIP]
> The interactive demo environment is a great way to get your feet wet testing out how Wiretap works. It provides an ideal network environment, ensuring you can focus on learning how to use Wiretap as intended without getting stuck troubleshooting weird network errors that you often encounter in the real world.

# Experimental

## TCP Tunneling

> [!WARNING]
> Performance will suffer, only use TCP Tunneling as a last resort

If you have *no* outbound or inbound UDP access, you can still use Wiretap, but you'll need to tunnel WireGuard traffic through TCP. This should only be used as a last resort. From WireGuard's [Known Limitations](https://www.wireguard.com/known-limitations/) page:
> **TCP Mode**
>
> WireGuard explicitly does not support tunneling over TCP, due to the classically terrible network performance of tunneling TCP-over-TCP. Rather, transforming WireGuard's UDP packets into TCP is the job of an upper layer of obfuscation (see previous point), and can be accomplished by projects like [udptunnel](https://github.com/rfc1036/udptunnel) and [udp2raw](https://github.com/wangyu-/udp2raw-tunnel).

Another great tool that has similar cross-platform capabilities to Wiretap is [Chisel](https://github.com/jpillora/chisel). We can use chisel to forward a UDP port to the remote system over TCP. To use:

Run `chisel server` on the wiretap client system, specifying a TCP port you can reach from the server system:
```bash
./chisel server --port 8080
```

> [!Note]
> In this example we run the `chisel server ...` command on the Wiretap *client*, and `chisel client ...` command  on a Wiretap *server*. This is because the chisel "client" always tries to reach out and connect to the chisel "server," whereas Wiretap clients and servers are defined by their functionality since either can initiate the connection.

In this example, we're connecting chisel to the listener on 8080 (on the wiretap client) and forwarding 61820/udp from the Wiretap server to 51820 (any interface) on the Wiretap client:
```bash
./chisel client <wiretap client address>:8080 61820:0.0.0.0:51820/udp
```
- `8080` is the chisel listening port specified in the `chisel server` command above
- `61820` is the localhost port on the Wiretap server that will be forwarded back to the Wiretap client.
- `51820` is the port where the Wiretap client is listening (by default is the same port you specified in the `--endpoint` argument in the initial `wiretap configure` command)

Finally, run Wiretap on the remote server system with the forwarded localhost port in the `--endpoint`:
```bash
WIRETAP_RELAY_INTERFACE_PRIVATEKEY=<key> WIRETAP_RELAY_PEER_PUBLICKEY=<key> WIRETAP_E2EE_INTERFACE_PRIVATEKEY=<key> WIRETAP_E2EE_PEER_PUBLICKEY=<key> WIRETAP_E2EE_PEER_ENDPOINT=172.16.0.1:51821 ./wiretap serve --endpoint localhost:61820
```

## Add Clients To Any Server

> [!NOTE]
> Clients added to arbitrary servers do not currently have the same capabilities as clients added to first-hop servers (the default)

Clients can be attached to any server in the network by using the `--server-address <api-address>` argument when running `wiretap add client`. This allows a client on a different network than the first client to still gain access to all of the Wiretap network's routes. But this has some limitations.

In this example, a new client (C2) is added to the second server in the right branch of a Wiretap network (S4). This client will only be able to access routes via the right branch of the network (S3 and S4) and not the left branch (S1 or S2) because the branches are only joined through an existing client (C1), which does not route traffic from other clients:

```
         ┌──────┐
         │  C1  │
         └┬────┬┘
          │    │
    ┌─────┴┐  ┌┴─────┐
    │  S1  │  │  S3  │
    └──┬───┘  └──┬───┘
       │         │
    ┌──┴───┐  ┌──┴───┐
    │  S2  │  │  S4  ◄───────┐
    └──────┘  └──────┘       │
                          ┌──┴───┐
                          │  C2  │
                          └──────┘
```

You may also need to manually edit the resulting `wiretap.conf` for the new client to remove any `AllowedIPs` entries that already exist in the new client's host routing table. If the server that the client is attaching to has a route for 10.2.0.0/16, but the Client already has that route (because that's where it lives), then remove the `10.2.0.0/16` entry from the `wiretap.conf` file before importing into WireGuard. Leave the API address and any other routes you wish to access.
