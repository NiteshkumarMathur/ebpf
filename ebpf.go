package main

import (
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

const iface = "eth0" // example of network interface

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: go run main.go <port>")
		return
	}

	port := uint16(4040)
	fmt.Sscanf(os.Args[1], "%d", &port)

	// locking memory for ebpf resources
	if err := rlimit.RemoveMemlock(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to remove memlock: %v\n", err)
		os.Exit(1)
	}
	// loading ebpf object
	spec, err := ebpf.LoadCollectionSpec("xdp_prog.o")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load xdp object: %v\n", err)
		os.Exit(1)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create collection: %v\n", err)
		os.Exit(1)
	}
	defer coll.Close()

	prog := coll.Programs["xdp_prog"]
	if prog == nil {
		fmt.Fprintf(os.Stderr, "program 'xdp_prog' not found\n")
		os.Exit(1)
	}

	// Attach the XDP program
	link, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface,
		Flags:     link.XDPMultiBuffer,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to attach xdp program: %v\n", err)
		os.Exit(1)
	}
	defer link.Close()

	// Configure the port from userspace
	dropPortMap := coll.Maps["drop_port_map"]
	if dropPortMap == nil {
		fmt.Fprintf(os.Stderr, "map 'drop_port_map' not found\n")
		os.Exit(1)
	}

	key := uint32(0)
	err = dropPortMap.Update(&key, &port, ebpf.UpdateAny)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to update map: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Dropping TCP packets on port %d\n", port)

	// Keep the program running
	select {}
}
