package snf

/*
#include <snf.h>
*/
import "C"

import (
	"bytes"
	"net"
	"unsafe"
)

// IfAddrs is a structure to map Interfaces to Sniffer port numbers.
type IfAddrs struct {
	// interface name, as in ifconfig
	Name string
	// snf port number
	PortNum uint32
	// Maximum RX rings supported
	MaxRings int
	// MAC address
	MACAddr [6]byte
	// Maximum TX injection handles supported
	MaxInject int
	// Underlying port's state (DOWN or UP)
	LinkState int
	// Link Speed (bps)
	LinkSpeed uint64
}

func cvtIfAddrs(ifa *C.struct_snf_ifaddrs) *IfAddrs {
	return &IfAddrs{
		Name:      C.GoString(ifa.snf_ifa_name),
		PortNum:   uint32(ifa.snf_ifa_portnum),
		MaxRings:  int(ifa.snf_ifa_maxrings),
		MACAddr:   *(*[6]byte)(unsafe.Pointer(&ifa.snf_ifa_macaddr[0])),
		MaxInject: int(ifa.snf_ifa_maxinject),
		LinkState: int(ifa.snf_ifa_link_state),
		LinkSpeed: uint64(ifa.snf_ifa_link_speed),
	}
}

// GetIfAddrs gets a list of Sniffer-capable ethernet devices.
func GetIfAddrs() (res []IfAddrs, err error) {
	var head *C.struct_snf_ifaddrs
	if err = retErr(C.snf_getifaddrs(&head)); err == nil {
		for p := head; p != nil; p = p.snf_ifa_next {
			res = append(res, *cvtIfAddrs(p))
		}
		C.snf_freeifaddrs(head)
	}
	return
}

// GetIfAddrByHW gets a Sniffer-capable ethernet devices with matching
// MAC address.
func GetIfAddrByHW(addr net.HardwareAddr) (*IfAddrs, error) {
	list, err := GetIfAddrs()
	if err == nil {
		for _, ifa := range list {
			if bytes.Equal(addr, ifa.MACAddr[:]) {
				return &ifa, nil
			}
		}
	}
	return nil, err
}

// GetIfAddrByName returns a Sniffer-capable ethernet devices with matching
// name.
func GetIfAddrByName(name string) (*IfAddrs, error) {
	list, err := GetIfAddrs()
	if err == nil {
		for _, ifa := range list {
			if name == ifa.Name {
				return &ifa, nil
			}
		}
	}
	return nil, err
}

// PortMask returns a mask of all Sniffer-capable ports that
// have their link state set to UP and a mask
// of all Sniffer-capable ports.
// The least significant bit represents port 0.
//
// ENODEV is returned in case of an error
// obtaining port information.
func PortMask() (linkup, valid uint32, err error) {
	list, err := GetIfAddrs()
	if err == nil {
		for i, _ := range list {
			ifa := &list[i]
			bit := uint32(1) << ifa.PortNum
			if valid |= bit; ifa.LinkState == LinkUp {
				linkup |= bit
			}
		}
	}
	return linkup, valid, err
}
