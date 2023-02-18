module wiretap

go 1.19

replace golang.zx2c4.com/wireguard => github.com/luker983/wireguard-go v0.0.0-20221104205540-da3a7e2ca548

//replace golang.zx2c4.com/wireguard => ../custom-wireguard-go

require (
	github.com/atotto/clipboard v0.1.4
	github.com/fatih/color v1.13.0
	github.com/go-ping/ping v1.1.0
	github.com/google/gopacket v1.1.19
	github.com/libp2p/go-reuseport v0.2.0
	github.com/spf13/cobra v1.6.1
	golang.org/x/net v0.7.0
	golang.zx2c4.com/wireguard v0.0.0-20220920152132-bb719d3a6e2c
	golang.zx2c4.com/wireguard/wgctrl v0.0.0-20221104135756-97bc4ad4a1cb
	gvisor.dev/gvisor v0.0.0-20220817001344-846276b3dbc5
)

require (
	github.com/google/btree v1.1.2 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/inconshreveable/mousetrap v1.0.1 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.16 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	golang.org/x/crypto v0.1.0 // indirect
	golang.org/x/sync v0.1.0 // indirect
	golang.org/x/sys v0.5.0 // indirect
	golang.org/x/time v0.1.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20211104114900-415007cec224 // indirect
)
