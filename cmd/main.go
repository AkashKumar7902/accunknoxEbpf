package main

import (
    "fmt"
    "log"
    "os"
    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
    "github.com/vishvananda/netlink"
)

const defaultPort uint16 = 4040

func main() {
    iface := "eth0" // Change this to your network interface
    port := defaultPort

    if len(os.Args) > 1 {
        var err error
        port, err = parsePort(os.Args[1])
        if err != nil {
            log.Fatalf("Invalid port: %v", err)
        }
    }

    // Load eBPF program
    objs := ebpfObjects{}
    if err := loadEbpfObjects(&objs, nil); err != nil {
        log.Fatalf("loading objects: %v", err)
    }
    defer objs.Close()

    // Set the port in the BPF map
    key := uint32(0)
    if err := objs.PortMap.Update(&key, &port, ebpf.UpdateAny); err != nil {
        log.Fatalf("updating port map: %v", err)
    }

    // Attach eBPF program to network interface
    nlLink, err := netlink.LinkByName(iface)
    if err != nil {
        log.Fatalf("getting link by name: %v", err)
    }

    link, err := link.AttachXDP(link.XDPOptions{
        Program:   objs.XdpDropTcp,
        AttachMode: link.XdpAttachMode(link.XDPAttachGeneric),
        Interface: nlLink.Attrs().Index,
    })
    if err != nil {
        log.Fatalf("attaching XDP program: %v", err)
    }
    defer link.Close()

    fmt.Printf("eBPF program attached to interface %s, dropping TCP packets on port %d\n", iface, port)

    // Keep the program running
    select {}
}

func parsePort(portStr string) (uint16, error) {
    var port uint16
    _, err := fmt.Sscanf(portStr, "%d", &port)
    return port, err
}
