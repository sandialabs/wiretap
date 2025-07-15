

# Wiretap Unit Tests
Commands prefaced with ! run on Client
Commands prefaced with @ run on Server
Commands prefaced with % run on Target 1
COPYCONF means to copy the appropriate configuration files to the Server and Target
WAIT X means to wait at least X seconds before continuing
EXIT means stop processing the commands; used for debugging


All tests should be run independently

## Initialization
```
! rm *.conf
@ rm *.conf
% rm *.conf

@ pkill wiretap
% pkill wiretap

! pkill socat
@ pkill socat
% pkill socat
```

## Inbound Configuration Tests
### ICT 1/8
Basic configuration
```
! ./wiretap configure -e 10.1.0.2:51690 --routes 10.2.0.0/16,fd:2::/64 >/dev/null
COPYCONF
@ ./wiretap serve -f ./wiretap_server.conf &
! wg-quick up ./wiretap_relay.conf >/dev/null 2>&1 && wg-quick up ./wiretap.conf >/dev/null 2>&1
WAIT 5
! ping -c2 -W1 10.2.0.4
! curl -m3 -I 10.2.0.4 | grep 200
! ./wiretap status
! wg-quick down ./wiretap.conf && wg-quick down ./wiretap_relay.conf

Clean Up:
! rm *.conf
@ rm *.conf
@ pkill wiretap
```

Expected Output:
- wiretap_relay.conf : Wiretap Interface Listener Port == 51690
- wiretap_server.conf : Wiretap Relay Interface Port == 51820
- wiretap_server.conf : Wiretap Relay Peer Endpoint Port == 51690
Expected Ping Output:
- Client returns at least one line containing the substring "bytes from 10.2.0.4"
- Server returns line containing substring "Transport: ICMP -> 10.2.0.4"
Expected Curl Output:
- Client returns a line containing the substring "200 OK"
- Server returns line containing substring "Transport: TCP -> 10.2.0.4:80"


### ICT 2/8
Simple mode
```
! ./wiretap configure -e 10.1.0.2:51690 --routes 10.2.0.0/16,fd:2::/64 --simple >/dev/null
COPYCONF
@ ./wiretap serve -f ./wiretap_server.conf &
! wg-quick up ./wiretap.conf >/dev/null 2>&1
WAIT 5
! ping -c2 -W1 10.2.0.4
! curl -m3 -I 10.2.0.4 | grep 200
! wg-quick down ./wiretap.conf

Clean Up:
! rm *.conf
@ rm *.conf
@ pkill wiretap
```

Expected Output:
- wiretap.conf : Wiretap Interface Listener Port == 51690
- wiretap_server.conf : Wiretap Relay Interface Port == 51820
- wiretap_server.conf : Wiretap Relay Peer Endpoint Port == 51690
- Server outputs message: "E2EE peer public key missing, running Wiretap in simple mode"
Expected Ping Output:
- Client returns at least one line containing the substring "bytes from 10.2.0.4"
- Server returns line containing substring "Transport: ICMP -> 10.2.0.4"
Expected Curl Output:
- Client returns a line containing the substring "200 OK"
- Server returns line containing substring "Transport: TCP -> 10.2.0.4:80"


### ICT 3/8
Custom server port
```
! ./wiretap configure -e 10.1.0.2:51690 --routes 10.2.0.0/16,fd:2::/64 -S 8990 >/dev/null
COPYCONF
@ ./wiretap serve -f ./wiretap_server.conf &
! wg-quick up ./wiretap_relay.conf >/dev/null 2>&1 && wg-quick up ./wiretap.conf >/dev/null 2>&1
WAIT 5
! ping -c2 -W1 10.2.0.4
! curl -m3 -I 10.2.0.4 | grep 200
! ./wiretap status
! wg-quick down ./wiretap.conf && wg-quick down ./wiretap_relay.conf

Clean Up:
! rm *.conf
@ rm *.conf
@ pkill wiretap
```

Expected Output:
- wiretap_relay.conf : Wiretap Interface Listener Port == 51690
- wiretap_server.conf : Wiretap Relay Interface Port == 8990
- wiretap_server.conf : Wiretap Relay Peer Endpoint Port == 51690
Expected Ping Output:
- Client returns at least one line containing the substring "bytes from 10.2.0.4"
- Server returns line containing substring "Transport: ICMP -> 10.2.0.4"
Expected Curl Output:
- Client returns a line containing the substring "200 OK"
- Server returns line containing substring "Transport: TCP -> 10.2.0.4:80"


### ICT 4/8
Simple mode with custom server port
```
! ./wiretap configure -e 10.1.0.2:51690 --routes 10.2.0.0/16,fd:2::/64 -S 8990 --simple >/dev/null
COPYCONF
@ ./wiretap serve -f ./wiretap_server.conf &
! wg-quick up ./wiretap.conf
WAIT 5
! ping -c2 -W1 10.2.0.4
! curl -m3 -I 10.2.0.4 | grep 200
! wg-quick down ./wiretap.conf

Clean Up:
! rm *.conf
@ rm *.conf
@ pkill wiretap
```

Expected Output:
- wiretap.conf : Wiretap Interface Listener Port == 51690
- wiretap_server.conf : Wiretap Relay Interface Port == 8990
- wiretap_server.conf : Wiretap Relay Peer Endpoint Port == 51690
- Server outputs message: "E2EE peer public key missing, running Wiretap in simple mode"
Expected Ping Output:
- Client returns at least one line containing the substring "bytes from 10.2.0.4"
- Server returns line containing substring "Transport: ICMP -> 10.2.0.4"
Expected Curl Output:
- Client returns a line containing the substring "200 OK"
- Server returns line containing substring "Transport: TCP -> 10.2.0.4:80"


### ICT 5/8
Differing endpoint and listen ports with SOCAT bridge
```
! ./wiretap configure -e 10.1.0.2:51690 --routes 10.2.0.0/16,fd:2::/64 -p 51820 >/dev/null
! socat UDP-LISTEN:51690,fork,reuseaddr UDP:localhost:51820 &
COPYCONF
@ ./wiretap serve -f ./wiretap_server.conf &
! wg-quick up ./wiretap_relay.conf >/dev/null 2>&1 && wg-quick up ./wiretap.conf >/dev/null 2>&1
WAIT 5
! ping -c2 -W1 10.2.0.4
! curl -m3 -I 10.2.0.4 | grep 200
! ./wiretap status
! wg-quick down ./wiretap.conf && wg-quick down ./wiretap_relay.conf

Clean Up:
! rm *.conf
! pkill socat
@ rm *.conf
@ pkill wiretap
```

Expected Output:
- wiretap_relay.conf : Wiretap Interace Listener Port == 51820
- wiretap_server.conf : Wiretap Relay Peer Endpoint Port == 51690
Expected Ping Output:
- Client returns at least one line containing the substring "bytes from 10.2.0.4"
- Server returns line containing substring "Transport: ICMP -> 10.2.0.4"
Expected Curl Output:
- Client returns a line containing the substring "200 OK"
- Server returns line containing substring "Transport: TCP -> 10.2.0.4:80"


### ICT 6/8
Simple mode; differing endpoint and listen ports with SOCAT bridge
```
! ./wiretap configure -e 10.1.0.2:51690 --routes 10.2.0.0/16,fd:2::/64 -p 51820 --simple >/dev/null
! socat UDP-LISTEN:51690,fork,reuseaddr UDP:localhost:51820 &
COPYCONF
@ ./wiretap serve -f ./wiretap_server.conf &
! wg-quick up ./wiretap.conf >/dev/null
WAIT 5
! ping -c2 -W1 10.2.0.4
! curl -m3 -I 10.2.0.4 | grep 200
! ./wiretap status
! wg-quick down ./wiretap.conf

Clean Up:
! rm *.conf
! pkill socat
@ rm *.conf
@ pkill wiretap
```

Expected Output:
- Server outputs message: "E2EE peer public key missing, running Wiretap in simple mode"
- wiretap.conf : Wiretap Interface Listener Port == 51820
- wiretap_server.conf : Wiretap Relay Peer Endpoint Port == 51690
Expected Ping Output:
- Client returns at least one line containing the substring "bytes from 10.2.0.4"
- Server returns line containing substring "Transport: ICMP -> 10.2.0.4"
Expected Curl Output:
- Client returns a line containing the substring "200 OK"
- Server returns line containing substring "Transport: TCP -> 10.2.0.4:80"


### ICT 7/8
Differing endpoint and listen ports with SOCAT bridge; custom server port
```
! ./wiretap configure -e 10.1.0.2:51690 --routes 10.2.0.0/16,fd:2::/64 -p 51820 -S 8796 >/dev/null
! socat UDP-LISTEN:51690,fork,reuseaddr UDP:localhost:51820 &
COPYCONF
@ ./wiretap serve -f ./wiretap_server.conf &
! wg-quick up ./wiretap_relay.conf >/dev/null 2>&1 && wg-quick up ./wiretap.conf >/dev/null 2>&1
WAIT 5
! ping -c2 -W1 10.2.0.4
! curl -m3 -I 10.2.0.4 | grep 200
! ./wiretap status
! wg-quick down ./wiretap.conf && wg-quick down ./wiretap_relay.conf

Clean Up:
! rm *.conf
! pkill socat
@ rm *.conf
@ pkill wiretap
```

Expected Output:
- wiretap_relay.conf : Wiretap Interface Listener Port == 51820
- wiretap_server.conf : Wiretap Relay Peer Endpoint Port == 51690
- wiretap_server.conf : Wiretap Relay Interface Port == 8796
Expected Ping Output:
- Client returns at least one line containing the substring "bytes from 10.2.0.4"
- Server returns line containing substring "Transport: ICMP -> 10.2.0.4"
Expected Curl Output:
- Client returns a line containing the substring "200 OK"
- Server returns line containing substring "Transport: TCP -> 10.2.0.4:80"


### ICT 8/8
Simple mode; differing endpoint and listen ports with SOCAT bridge; custom server port
```
! ./wiretap configure -e 10.1.0.2:51690 --routes 10.2.0.0/16,fd:2::/64 -p 51820 -S 8796 --simple >/dev/null
! socat UDP-LISTEN:51690,fork,reuseaddr UDP:localhost:51820 &
COPYCONF
@ ./wiretap serve -f ./wiretap_server.conf &
! wg-quick up ./wiretap.conf >/dev/null
WAIT 5
! ping -c2 -W1 10.2.0.4
! curl -m3 -I 10.2.0.4 | grep 200
! ./wiretap status
! wg-quick down ./wiretap.conf

Clean Up:
! rm *.conf
! pkill socat
@ rm *.conf
@ pkill wiretap
```

Expected Output:
- Server outputs message: "E2EE peer public key missing, running Wiretap in simple mode"
- wiretap.conf : Wiretap Interface Listener Port == 51820
- wiretap_server.conf : Wiretap Relay Peer Endpoint Port == 51690
- wiretap_server.conf : Wiretap Relay Interface Port == 8796
Expected Ping Output:
- Client returns at least one line containing the substring "bytes from 10.2.0.4"
- Server returns line containing substring "Transport: ICMP -> 10.2.0.4"
Expected Curl Output:
- Client returns a line containing the substring "200 OK"
- Server returns line containing substring "Transport: TCP -> 10.2.0.4:80"


## Outbound Configuration Tests
### OCT 1/4
Basic outbound configuration
```
! ./wiretap configure -o 10.1.0.3:8990 --routes 10.2.0.0/16,fd:2::/64 >/dev/null
COPYCONF
@ ./wiretap serve -f ./wiretap_server.conf &
! wg-quick up ./wiretap_relay.conf >/dev/null 2>&1 && wg-quick up ./wiretap.conf >/dev/null 2>&1
WAIT 5
! ping -c2 -W1 10.2.0.4
! curl -m3 -I 10.2.0.4 | grep 200
! ./wiretap status
! wg-quick down ./wiretap.conf && wg-quick down ./wiretap_relay.conf

Clean Up:
! rm *.conf
@ rm *.conf
@ pkill wiretap
```

Expected Output:
- wiretap.conf : Wiretap Interface Port == 51820
- wiretap.conf : Wiretap Peer Endpoint Port == 8990
Expected Ping Output:
- Client returns at least one line containing the substring "bytes from 10.2.0.4"
- Server returns line containing substring "Transport: ICMP -> 10.2.0.4"
Expected Curl Output:
- Client returns a line containing the substring "200 OK"
- Server returns line containing substring "Transport: TCP -> 10.2.0.4:80"


### OCT 2/4
Simple mode
```
! ./wiretap configure -o 10.1.0.3:8990 --routes 10.2.0.0/16,fd:2::/64 --simple >/dev/null
COPYCONF
@ ./wiretap serve -f ./wiretap_server.conf &
! wg-quick up ./wiretap.conf >/dev/null
WAIT 5
! ping -c2 -W1 10.2.0.4
! curl -m3 -I 10.2.0.4 | grep 200
! ./wiretap status
! wg-quick down ./wiretap.conf

Clean Up:
! rm *.conf
@ rm *.conf
@ pkill wiretap
```

Expected Output:
- wiretap.conf : Wiretap Interface Port == 51820
- wiretap.conf : Wiretap Peer Endpoint Port == 8990
- Server outputs message: E2EE peer public key missing, running Wiretap in simple mode.
Expected Ping Output:
- Client returns at least one line containing the substring "bytes from 10.2.0.4"
- Server returns line containing substring "Transport: ICMP -> 10.2.0.4"
Expected Curl Output:
- Client returns a line containing the substring "200 OK"
- Server returns line containing substring "Transport: TCP -> 10.2.0.4:80"


### OCT 3/4
Custom client listening port and custom implicit server port
```
! ./wiretap configure -o 10.1.0.3:8990 --routes 10.2.0.0/16,fd:2::/64 -p 56790 >/dev/null
COPYCONF
@ ./wiretap serve -f ./wiretap_server.conf &
! wg-quick up ./wiretap_relay.conf >/dev/null 2>&1 && wg-quick up ./wiretap.conf >/dev/null 2>&1
WAIT 5
! ping -c2 -W1 10.2.0.4
! curl -m3 -I 10.2.0.4 | grep 200
! ./wiretap status
! wg-quick down ./wiretap.conf && wg-quick down ./wiretap_relay.conf

Clean Up:
! rm *.conf
@ rm *.conf
@ pkill wiretap
```

Unexpected Output: 
- ERROR: 2025/07/10 13:37:37 peer(L/Oa…nLCA) - Failed to send handshake initiation: no known endpoint for peer
Expected Output:
- wiretap_relay.conf : Wiretap Listen Port == 56790
- wiretap_relay.conf : Wiretap Peer Endpoint Port == 8990
Expected Ping Output:
- Client returns at least one line containing the substring "bytes from 10.2.0.4"
- Server returns line containing substring "Transport: ICMP -> 10.2.0.4"
Expected Curl Output:
- Client returns a line containing the substring "200 OK"
- Server returns line containing substring "Transport: TCP -> 10.2.0.4:80"


### OCT 4/4
Simple mode; custom client listening port and custom implicit server port
```
! ./wiretap configure -o 10.1.0.3:8990 --routes 10.2.0.0/16,fd:2::/64 -p 56790 --simple >/dev/null
COPYCONF
@ ./wiretap serve -f ./wiretap_server.conf &
! wg-quick up ./wiretap.conf >/dev/null
WAIT 5
! ping -c2 -W1 10.2.0.4
! curl -m3 -I 10.2.0.4 | grep 200
! ./wiretap status
! wg-quick down ./wiretap.conf

Clean Up:
! rm *.conf
@ rm *.conf
@ pkill wiretap
```

Expected Output:
- wiretap.conf : Wiretap Interface Port == 56790
- wiretap.conf : Wiretap Peer Endpoint Port == 8990
- Server outputs message: E2EE peer public key missing, running Wiretap in simple mode.
Expected Ping Output:
- Client returns at least one line containing the substring "bytes from 10.2.0.4"
- Server returns line containing substring "Transport: ICMP -> 10.2.0.4"
Expected Curl Output:
- Client returns a line containing the substring "200 OK"
- Server returns line containing substring "Transport: TCP -> 10.2.0.4:80"


## Inbound/Outbound Configuration Error Tests
### IOCET 1/3
Conflicting endpoint arguments
```
! ./wiretap configure -e 10.1.0.2:51690 --routes 10.2.0.0/16,fd:2::/64 -o 10.1.0.3:8990

Expected Output:
- Error Msg: Error: if any flags in the group [endpoint outbound-endpoint] are set none of the others can be; [endpoint outbound-endpoint] were all set
```
### IOCET 2/3
Missing routes
```
! ./wiretap configure -e 10.1.0.2:51690

Expected Output:
- Error Msg: required flag(s) "routes" not set
```

### IOCET 3/3
Missing endpoint
```
! ./wiretap configure --routes 10.2.0.0/16,fd:2::/64

Expected Output:
- Error Msg: at least one of the flags in the group [endpoint outbound-endpoint] is required
```

## Add Server Configuration
### ASCT 1/4
Connect new server to custom listen port
```
! ./wiretap configure -e 10.1.0.2:51690 --routes 10.2.0.0/16,fd:2::/64 -S 8990 >/dev/null
COPYCONF
@ ./wiretap serve -f ./wiretap_server.conf &
! wg-quick up ./wiretap_relay.conf >/dev/null 2>&1 && wg-quick up ./wiretap.conf >/dev/null 2>&1
WAIT 5
! ./wiretap add server --server-address ::2 -e 10.2.0.3:8990 --routes 10.3.0.0/16,fd:3::/64 >/dev/null 2>&1
COPYCONF
% ./wiretap serve -f ./wiretap_server1.conf &
! wg-quick down ./wiretap.conf && wg-quick up ./wiretap.conf >/dev/null 2>&1
WAIT 15
! ping -c2 -W1 10.3.0.5
! curl -m3 -I 10.3.0.5 | grep 200
! ./wiretap status
! wg-quick down ./wiretap.conf && wg-quick down ./wiretap_relay.conf

Clean Up:
! rm *.conf
@ rm *.conf
@ pkill wiretap
% rm *.conf
% pkill wiretap
```

Expected Output:
- Server outputs message containing substring "API: Peer Added:"
- wiretap_relay.conf : Wiretap Interface Listener Port == 51690
- wiretap_server.conf : Wiretap Relay Interface Port == 8990
- wiretap_server.conf : Wiretap Relay Peer Endpoint Port == 51690
- wiretap_server1.conf : Wiretap Relay Interface Port == 51820
Expected Ping Output:
- Client returns at least one line containing the substring "bytes from 10.3.0.5"
- Server returns line containing substring "Transport: ICMP -> 10.3.0.5"
Expected Curl Output:
- Client returns a line containing the substring "200 OK"
- Server returns line containing substring "Transport: TCP -> 10.3.0.5:80"

### ASCT 2/4
Connect new outbound server with custom listen port
```
! ./wiretap configure -e 10.1.0.2:51690 --routes 10.2.0.0/16,fd:2::/64 -S 8990 >/dev/null
COPYCONF
@ ./wiretap serve -f ./wiretap_server.conf &
! wg-quick up ./wiretap_relay.conf >/dev/null 2>&1 && wg-quick up ./wiretap.conf >/dev/null 2>&1
WAIT 5
! ./wiretap add server --server-address ::2 -o 10.2.0.4:8990 --routes 10.3.0.0/16,fd:3::/64 >/dev/null 2>&1
COPYCONF
% ./wiretap serve -f ./wiretap_server1.conf &
! wg-quick down ./wiretap.conf && wg-quick up ./wiretap.conf >/dev/null 2>&1
WAIT 15
! ping -c2 -W1 10.3.0.5
! curl -m3 -I 10.3.0.5 | grep 200
! ./wiretap status
! wg-quick down ./wiretap.conf && wg-quick down ./wiretap_relay.conf

Clean Up:
! rm *.conf
@ rm *.conf
@ pkill wiretap
% rm *.conf
% pkill wiretap
```

Expected Output:
- Server outputs message containing substring "API: Peer Added:"
- wiretap_relay.conf : Wiretap Interface Listener Port == 51690
- wiretap_server.conf : Wiretap Relay Interface Port == 8990
- wiretap_server.conf : Wiretap Relay Peer Endpoint Port == 51690
- wiretap_server1.conf : Wiretap Relay Interface Port == 8976


### ASCT 3/4
Add server with mismatched listen port and endpoint; socat bridge
```
! ./wiretap configure -e 10.1.0.2:51690 --routes 10.2.0.0/16,fd:2::/64 -S 8990 >/dev/null
COPYCONF
@ ./wiretap serve -f ./wiretap_server.conf &
! wg-quick up ./wiretap_relay.conf >/dev/null 2>&1 && wg-quick up ./wiretap.conf >/dev/null 2>&1
WAIT 5
! ./wiretap add server --server-address ::2 -e 10.2.0.3:51820 --routes 10.3.0.0/16,fd:3::/64 -p 8990 >/dev/null 2>&1
COPYCONF
@ socat UDP-LISTEN:51820,fork,reuseaddr UDP:localhost:8990 &
% ./wiretap serve -f ./wiretap_server1.conf &
! wg-quick down ./wiretap.conf && wg-quick up ./wiretap.conf >/dev/null 2>&1
WAIT 15
! ping -c2 -W1 10.3.0.5
! curl -m3 -I 10.3.0.5 | grep 200
! ./wiretap status
! wg-quick down ./wiretap.conf && wg-quick down ./wiretap_relay.conf

Clean Up:
! rm *.conf
@ rm *.conf
@ pkill wiretap
@ pkill socat
% rm *.conf
% pkill wiretap
```

Expected Output:
- Server outputs message containing substring "API: Peer Added:"
- wiretap_relay.conf : Wiretap Interface Listener Port == 51690
- wiretap_server.conf : Wiretap Relay Interface Port == 8990
- wiretap_server.conf : Wiretap Relay Peer Endpoint Port == 51690
- wiretap_server1.conf : Wiretap Relay Interface Port == 8976
Expected Ping Output:
- Client returns at least one line containing the substring "bytes from 10.3.0.5"
- Server returns line containing substring "Transport: ICMP -> 10.3.0.5"
Expected Curl Output:
- Client returns a line containing the substring "200 OK"
- Server returns line containing substring "Transport: TCP -> 10.3.0.5:80"


### ASCT 4/4
Invalid- trying to start two servers on first jump but access third network
```
! ./wiretap configure -e 10.1.0.2:51690 --routes 10.2.0.0/16,fd:2::/64 -S 8990 >/dev/null
COPYCONF
@ ./wiretap serve -f ./wiretap_server.conf &
! wg-quick up ./wiretap_relay.conf >/dev/null 2>&1 && wg-quick up ./wiretap.conf >/dev/null 2>&1
WAIT 5
! ./wiretap add server -e 10.1.0.2:51690 --routes 10.3.0.0/16,fd:3::/64 >/dev/null 2>&1
COPYCONF
@ ./wiretap serve -f ./wiretap_server1.conf &
! wg-quick down ./wiretap.conf && wg-quick down ./wiretap_relay.conf
! wg-quick up ./wiretap_relay.conf >/dev/null 2>&1 && wg-quick up ./wiretap.conf >/dev/null 2>&1
WAIT 15
! ping -c2 -W1 10.3.0.5
! curl -m3 -I 10.3.0.5 | grep 200
! ./wiretap status
! wg-quick down ./wiretap.conf && wg-quick down ./wiretap_relay.conf

Clean Up:
! rm *.conf
@ rm *.conf
@ pkill wiretap
% rm *.conf
% pkill wiretap
```

Expected Output:
- FAIL: cannot route to 10.3.0.0/16
- Server outputs message containing substring "API: Peer Added:"
- wiretap_relay.conf : Wiretap Interface Listener Port == 51690
- wiretap_server.conf : Wiretap Relay Interface Port == 8990
- wiretap_server.conf : Wiretap Relay Peer Endpoint Port == 51690
- wiretap_server1.conf : Wiretap Relay Interface Port == 51820
