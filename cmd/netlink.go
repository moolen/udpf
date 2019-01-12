package main

import (
	"fmt"
	"log"
	"syscall"

	"github.com/iovisor/gobpf/elf"
	"github.com/vishvananda/netlink"
)

func createQdisc(link netlink.Link) (func(), error) {
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	cleanup := func() {
		netlink.QdiscDel(qdisc)
	}
	if err := netlink.QdiscReplace(qdisc); err != nil {
		return nil, fmt.Errorf("netlink: creating qdisc for %s failed: %s", link.Attrs().Name, err)
	}
	log.Printf("netlink: creating qdisc for %s succeeded\n", link.Attrs().Name)
	return cleanup, nil
}

func createFilter(prog *elf.SchedProgram, link netlink.Link, parent uint32) (func(), error) {
	filter := &netlink.U32{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    parent,
			Handle:    netlink.MakeHandle(0, 1),
			Priority:  1,
			Protocol:  syscall.ETH_P_ALL,
		},
		ClassId: netlink.MakeHandle(1, 1),
		Actions: []netlink.Action{
			&netlink.BpfAction{
				Fd:   prog.Fd(),
				Name: prog.Name,
			},
		},
	}
	cleanup := func() {
		netlink.FilterDel(filter)
	}
	err := netlink.FilterAdd(filter)
	if err != nil {
		return cleanup, fmt.Errorf("failed to add filter: %s", err)
	}
	log.Printf("successfully added filter for %s \n", prog.Name)
	return cleanup, nil
}
