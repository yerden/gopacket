// Copyright 2019 Yerden Zhumabekov. All rights reserved.
//
// Use of this source code is governed by MIT license which can be found in the
// LICENSE file in the root of the source tree.

package snf

// #include <snf.h>
import "C"

import (
	"fmt"
	"os"
	"unsafe"
)

// ReflectHandle wraps SNF reflect capability.
//
// Network packets acquired through Sniffer can be reflected back into the
// kernel path as if the device had initially sent then through to the regular
// network stack.  While Sniffer users are typically expected to process a
// significant portion of their packets with less overhead in userspace, this
// feature is provided as a convenience to allow some packets to be processed
// back in the kernel. The implementation makes no explicit step to make the
// kernel-based processing any faster than it is when Sniffer is not being used
// (in fact, it is probably much slower).
type ReflectHandle struct {
	sigCh <-chan os.Signal
	dev   C.snf_netdev_reflect_t
}

// ReflectEnable enables a network device for packet reflection and returns
// ReflectHandle.
//
// As stated in SNF documentation, this call is always a success.
func (h *Handle) ReflectEnable() (*ReflectHandle, error) {
	ref := &ReflectHandle{
		dev: nil,
	}
	return ref, retErr(C.snf_netdev_reflect_enable(handle(h), &ref.dev))
}

// NotifyWith installs signal notification channel which is presumably
// registered via signal.Notify.
func (ref *ReflectHandle) NotifyWith(ch <-chan os.Signal) {
	ref.sigCh = ch
}

func (ref *ReflectHandle) checkSignal() error {
	if ch := ref.sigCh; ch != nil {
		select {
		case sig := <-ch:
			return fmt.Errorf("caught: %v", sig)
		default:
		}
	}
	return nil
}

// Reflect a packet to the network device.
//
// pkt should hold the packet to be reflected to the network device. It should
// contain a complete Ethernet frame (without the trailing CRC) and start with
// a valid Ethernet header.
//
// As stated in SNF documentation, this call is always a success. This
// package's Reflect will return io.EOF error in case the underlying Handle is
// about to close due to signal or user Close call.
func (ref *ReflectHandle) Reflect(pkt []byte) error {
	if err := ref.checkSignal(); err != nil {
		return err
	}
	return retErr(C.snf_netdev_reflect(ref.dev, unsafe.Pointer(&pkt[0]), C.uint(len(pkt))))
}
