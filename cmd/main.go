package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/vishvananda/netlink"
)

const (
	bpfSource   = "bpf.c"
	bpfBytecode = "bpf.o"
)

var (
	cfg = &config{
		mu: sync.Mutex{},
	}
)

type config struct {
	mu         sync.Mutex
	iface      string
	targetHost string
	targetPort int
}

func main() {
	flag.StringVar(&cfg.iface, "iface", "", "name of device")
	flag.StringVar(&cfg.targetHost, "target", "", "target address")
	flag.IntVar(&cfg.targetPort, "port", 8125, "target port")
	flag.Parse()
	log.Printf("%#v", cfg)

	mod, err := compile(cfg)
	if err != nil {
		panic(err)
	}

	var waiter sync.WaitGroup
	waiter.Add(1)
	var sig chan os.Signal
	sig = make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		waiter.Done()
	}()

	// setup tc qdisc & filter
	link, err := netlink.LinkByName(cfg.iface)
	if err != nil {
		panic(err)
	}
	cleanupQdisc, err := createQdisc(link)
	if err != nil {
		panic(err)
	}
	defer cleanupQdisc()
	cleanupIngressAct, err := createFilter(
		mod.SchedProgram("sched_act/ingress_action"),
		link,
		netlink.HANDLE_MIN_INGRESS,
	)
	if err != nil {
		panic(err)
	}
	defer cleanupIngressAct()

	go runServer()
	log.Printf("waiting for ctrl-c")
	waiter.Wait()

	cleanup(link)
}

func cleanup(link netlink.Link) {
	log.Printf("cleaning up")
	err := netlink.QdiscDel(&netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	})
	if err != nil {
		log.Printf("failed to remove qdisc from %s", link.Attrs().Name)
	}
	log.Printf("done")
}

func (c *config) targetAddr() (uint32, error) {
	ips, err := net.LookupIP(c.targetHost)
	if err != nil {
		return 0, fmt.Errorf("could not lookup hostname: %s", err)
	}
	log.Printf("resolved %s to %s", c.targetHost, ips[0].String())
	return transformBE(ips[0].To4()), nil
}
