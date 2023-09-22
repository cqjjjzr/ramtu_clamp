# IPv6 RA MTU Clamp

This utility acts as a Netfilter queue userspace program to manipulate the ICMPv6 ND-RA packets to clamp the MTU broadcast to a certain value.

Useful for situations such as IPv6-only site-to-site link-layer tunnels.

Example: Bridge one network with IPv6 connectivity (router and DHCPv6 servers on the link) with other networks without IPv6 connectivity using tunnels like GRETAP or VXLAN, without tunneling IPv4 traffic.
In this case you want the IPv4 MTU to be the normal value (e.g. 1500) but the IPv6 MTU to be a lower value to avoid fragmentation in tunnel.

## Build

This utility is Linux only. Requires libraries from `libnetfilter-queue` to build. 

On Ubuntu: 

```shell
sudo apt install libnetfilter-queue-dev 
cargo build --release
```

## Usage

1. Setup tunnels (`gretap0` for example)
2. Setup daemon of ramtu_clamp and enable/start the service. The program must be run as `root`. Example systemd unit file:
```unit
[Unit]
Description=IPv6 NDP-RA MTU Clamp

[Service]
ExecStart=/opt/ramtu_clamp --queue 1 --new-mtu 1280

[Install]
WantedBy=multi-user.target
```
3. Config netfilter queueing (on any side of the tunnel, the "provider" side in the example. If configured on the "consumer" side, then `oifname` should be changed to `iifname`). The example below setup the queueing on `bridge` tables.
```shell
nft add table bridge filter
nft add chain bridge filter postrouting '{type filter hook postrouting priority dstnat; }'
nft add rule bridge filter postrouting oifname gretap0 icmpv6 type 134 queue num 1
```

Note the queue number in the ramtu_clamp parameter and nftables rule must match.

### Command line arguments

- `-p <PCAP_FILE>`: Don't start Netfilter queue daemon, but use the specified pcap file to test. Must be used with `-l`. 
- `-n <NEW_MTU>`: New MTU value to use.
- `-q <QUEUE>`: Queue number.
- `-l`: Log out RA packets before and after manipulation.