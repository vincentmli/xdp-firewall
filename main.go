// This program demonstrates attaching an eBPF program to a network interface to block source IPs/CIDRs
// This example depends on bpf_link, available in Linux kernel version 5.7 or newer.
package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"path"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// set environment variable $BPF_CLANG and $BPF_CFLAGS.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf xdp_fw.c -- -I./headers

const (
	bpfFSPath = "/sys/fs/bpf"
)

func startTicker(f func()) chan bool {
	done := make(chan bool, 1)
	go func() {
		ticker := time.NewTicker(time.Second * 1)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				f()
			case <-done:
				fmt.Println("done")
				return
			}
		}
	}()
	return done
}

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("Please specify a network interface")
	}

	// Look up the network interface by name.
	ifaceName := os.Args[1]
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", ifaceName, err)
	}

	timedInternetMap := "timedInternetMap"

	pinPath := path.Join(bpfFSPath, timedInternetMap)
	if err := os.MkdirAll(pinPath, os.ModePerm); err != nil {
		log.Fatalf("failed to create bpf fs subpath: %+v", err)
	}

	// Load pre-compiled programs into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			// Pin the map to the BPF filesystem and configure the
			// library to automatically re-write it in the BPF
			// program so it can be re-used if it already exists or
			// create it if not
			PinPath: pinPath,
		},
	}); err != nil {
		log.Fatalf("loading objects: %s", err)
	}

	//from: https://xiongliuhua.com/ebpf/201/, populate the firewall map
	denyIPs := []string{"10.11.15.114/32", "127.0.0.1/32"}
	for index, ip := range denyIPs {

		if !strings.Contains(ip, "/") {

			ip += "/32"

		}
		_, ipnet, err := net.ParseCIDR(ip)

		if err != nil {
			log.Printf("malformed ip %v \n", err)
			continue
		}
		var res = make([]byte, objs.FirewallMap.KeySize())

		ones, _ := ipnet.Mask.Size()

		binary.LittleEndian.PutUint32(res, uint32(ones))

		copy(res[4:], ipnet.IP)
		if err := objs.FirewallMap.Put(res, uint32(index)); err != nil {
			log.Fatalf("FirewallMap put err %v \n", err)
		}
	}

	defer objs.Close()

	// Attach the program.
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.Firewall,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("could not attach XDP program: %s", err)
	}
	defer l.Close()

	log.Printf("Attached XDP program to iface %q (index %d)", iface.Name, iface.Index)
	log.Printf("Press Ctrl-C to exit and remove the program")

	done := startTicker(func() {
		fmt.Println("tick...")
	})
	time.Sleep(60 * time.Second)
	close(done)
	time.Sleep(5 * time.Second)

	// Print the contents of the BPF hash map (source IP address -> packet count).
	/*
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			log.Printf("Map contents:\n")
		}
	*/
}
