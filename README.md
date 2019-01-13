# udpf

udpf is a udp packet forwarder using eBPF in the traffic control layer.

## Prerequisites

* clang
* make
* go

## Installation

Use `make build TARGET=1.2.3.4` to build the go binary aswell as the bpf bytecode.

* Run `sudo ./udpf -iface xxxx` to load and inject the bpf bytecode into the tc ingress

## Testing

use docker-compose
```
$ docker-compose build; docker-compose up

# get address of udpf
$ docker inspect udpf_udpf_1 -f "{{.NetworkSettings.Networks.udpf_default.IPAddress}}"
> 172.22.0.4

# continuously send packets there
$ watch 'echo "omegalul" | nc -c -u 172.22.0.4 8125'

# dump udp traffic on all devices
$ sudo tcpdump -vvXX -eni any udp port 8125
# [bridge -> udpf] and [udpf -> target_one]
172.22.0.1.56511 > 172.22.0.4.8125: [udp sum ok] UDP, length 9
172.22.0.4.56511 > 172.22.0.2.8125: [udp sum ok] UDP, length 9

# check bpf debug output
$ sudo tc exec bpf dbg
nc-17894 [005] ..s1 16840.571481: 0: target: 33560236 48415
nc-17894 [005] ..s1 16840.571505: 0: fib lookup successful: addr= 33560236, dmac= ffff8b984a543c22, smac= ffff8b984a543c1c
nc-17894 [005] ..s1 16840.571513: 0: clone redirect succeeded

```

now recompile bytecode with new endpoint
```
$ curl -i "http://localhost:8080/reconfigure?target=reddit.com"


# traffic should go to target_two
$ sudo tcpdump -vvXX -eni any udp port 8125
# [bridge -> udpf] and [udpf -> target_two]
172.22.0.1.56511 > 172.22.0.4.8125: [udp sum ok] UDP, length 9
172.22.0.4.56511 > 172.22.0.3.8125: [udp sum ok] UDP, length 9

```

### Debugging

```
# check if progs are loaded properly
$ sudo bpftool prog list
[...]
103: sched_cls  tag 59904229c5a1f55d  gpl
	loaded_at 2019-01-12T15:28:29+0100  uid 0
	xlated 24B  jited 64B  memlock 4096B
104: sched_act  tag a0410ba1cee9558a  gpl
	loaded_at 2019-01-12T15:28:29+0100  uid 0
	xlated 3104B  jited 1820B  memlock 4096B

# send packet to device
$ echo "omegalul" | nc -c -u 127.0.0.1 8125

$ sudo tc exec bpf debug
nc-20303 [007] ..s1 17981.908325: 0: udp dest 8125
nc-20303 [007] ..s1 17981.908334: 0: fib lookup successful: addr= 393914560, dmac= ffff919eca5c3c22, smac= ffff919eca5c3c1c
nc-20303 [007] ..s1 17981.908345: 0: clone redirect succeeded


# if you see `packet not forwarded` do
$ echo 1 > /proc/sys/net/ipv4/ip_forward


# if you see: `no neighbor` do
# to update the fib table
$ ping -c 1 <TARGET>

# you might want to disable checksum offloading
sudo ethtool --offload <device> rx off tx off ; sudo ethtool -K <device> gso off

```

## TODO

* fix fib lookup if neighbor is not known (send packet up the stack)
* support ipv6


## Digging deeper

* Man pages `bpf(2)`, `tc-bpf(8)`
* everything upstream in kernel, llvm and iproute2
	* check out linux kernel examples at `samples/bpf`
	* check out examples from iproute2 at `examples/bpf`
	* LKML bpf_fib initial impl: https://www.mail-archive.com/netdev@vger.kernel.org/msg231391.html
* data plane programming with `P4`
	* http://vger.kernel.org/lpc_net2018_talks/p4-xdp-lpc18-paper.pdf
	* https://github.com/p4lang/p4c
* linux tc cls-act architecture
	* https://people.netfilter.org/pablo/netdev0.1/papers/Linux-Traffic-Control-Classifier-Action-Subsystem-Architecture.pdf
	* https://www.youtube.com/watch?v=cyeJYjZHv5M
