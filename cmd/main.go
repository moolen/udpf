package main

import (
	"bytes"
	"encoding/binary"
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

var (
	cfg *config
)

func main() {
	var err error
	iface := flag.String("iface", "", "name of device")
	target := flag.String("target", "", "target address")
	port := flag.Int("port", 8125, "target port")
	flag.Parse()

	cfg, err = newConfig(*iface, *target, *port)
	if err != nil {
		panic(err)
	}
	log.Printf("%#v", cfg)

	var waiter sync.WaitGroup
	waiter.Add(1)
	var sig chan os.Signal
	sig = make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		waiter.Done()
	}()

	configure()
	go runServer()
	log.Printf("waiting for ctrl-c")
	waiter.Wait()
	cleanup()
}

func configure() error {
	// FIXME: we need this to populate kernels fib table
	// it should be somehow possible to do this on the tc layer
	conn, err := net.Dial("udp", fmt.Sprintf("%s:%d", cfg.Hostname, cfg.Port))
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write([]byte("\n"))
	if err != nil {
		return err
	}
	mod, err := compile(cfg)
	if err != nil {
		return err
	}
	// setup tc qdisc & filter
	link, err := netlink.LinkByName(cfg.Interface)
	if err != nil {
		return err
	}
	err = createQdisc(link)
	if err != nil {
		return err
	}
	err = createFilter(
		mod.SchedProgram("sched_act/ingress_action"),
		link,
		netlink.HANDLE_MIN_INGRESS,
	)
	if err != nil {
		return err
	}
	return nil
}

func cleanup() {
	log.Printf("cleaning up")
	// setup tc qdisc & filter
	link, err := netlink.LinkByName(cfg.Interface)
	if err != nil {
		panic(err)
	}
	deleteQdisc(link)
	if err != nil {
		log.Printf("failed to remove qdisc from %s", link.Attrs().Name)
	}
	log.Printf("done")
}

type config struct {
	mu        sync.Mutex
	Interface string
	Hostname  string
	Address   uint32
	Port      uint16
}

func newConfig(iface string, hostname string, port int) (conf *config, err error) {
	conf = &config{
		mu:        sync.Mutex{},
		Interface: iface,
	}
	conf.UpdatePort(port)
	err = conf.UpdateHostname(hostname)
	if err != nil {
		return
	}
	return
}

// convert port to big endian
func (c *config) UpdatePort(port int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, uint16(port))
	c.Port = binary.LittleEndian.Uint16(buf)
}

func (c *config) UpdateHostname(hostname string) error {
	c.mu.Lock()
	c.Hostname = hostname
	c.mu.Unlock()
	return c.UpdateAddr()
}

func (c *config) UpdateAddr() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	ips, err := net.LookupIP(c.Hostname)
	if err != nil {
		return fmt.Errorf("could not lookup hostname: %s", err)
	}
	for _, ip := range ips {
		if ip.To4() != nil {
			log.Printf("resolved %s to %s", c.Hostname, ips[0].String())
			binary.Read(bytes.NewBuffer(ips[0].To4()), binary.LittleEndian, &c.Address)
			return nil
		}
	}
	return fmt.Errorf("ipv6 only host. ipv6 is not supported")
}
