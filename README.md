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

Build application
```
$ make build

# make sure there's someone at 172.17.0.2
$ sudo ./udpf -iface lo -target 172.17.0.2
```

..send packets..
```
$ echo "hello" | nc -c -u 127.0.0.1 8125
```

..check that they're being cloned..
```
$ sudo tcpdump -vvXX -eni any udp port 8125
15:34:18.416219 52:54:00:64:b4:4a > 52:54:00:23:a4:5c, ethertype IPv4 (0x0800), length 51: 127.0.0.1.56548 > 172.17.0.2.8125: UDP, length 9
	0x0000:  5254 0023 a45c 5254 0064 b44a 0800 4500  RT.#.\RT.d.J..E.
	0x0010:  0025 4000 4000 4011 4107 7f00 0001 c0a8  .%@.@.@.A.......
	0x0020:  7a17 dce4 1fbd 0011 4f7a 6f6d 6567 616c  z.......Ozomegal
	0x0030:  756c 0a                                  ul.

```

recompile bytecode with new endpoint
```
$ curl -i "http://localhost:8080/reconfigure?target=reddit.com"
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
* data plane programming with `P4`
	* http://vger.kernel.org/lpc_net2018_talks/p4-xdp-lpc18-paper.pdf
	* https://github.com/p4lang/p4c
* linux tc cls-act architecture
	* https://people.netfilter.org/pablo/netdev0.1/papers/Linux-Traffic-Control-Classifier-Action-Subsystem-Architecture.pdf
	* https://www.youtube.com/watch?v=cyeJYjZHv5M
