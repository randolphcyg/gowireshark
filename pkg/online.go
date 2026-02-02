package pkg

/*
#cgo pkg-config: glib-2.0
#cgo CFLAGS: -I${SRCDIR}/include
#cgo CFLAGS: -I${SRCDIR}/include/wireshark
#cgo CFLAGS: -I${SRCDIR}/include/libpcap

#include "lib.h"
#include "online.h"
#include "offline.h"
*/
import "C"
import (
	"log/slog"
	"sync"
	"unsafe"

	"github.com/bytedance/sonic"
	"github.com/pkg/errors"
)

// frameDataChanMap stores channels for live capture results, keyed by interface name.
var (
	frameDataChanMap = make(map[string]chan FrameData)
	mapMutex         sync.RWMutex
)

// FrameDataChan is the public map for accessing capture channels
var FrameDataChan = make(map[string]chan FrameData)

// PcapAddr represents an individual address (including address, netmask, broadcast address, and destination address).
type PcapAddr struct {
	Addr      string `json:"addr,omitempty"`      // Address (could be IPv4, IPv6, MAC, etc.)
	Netmask   string `json:"netmask,omitempty"`   // Netmask (if available)
	Broadaddr string `json:"broadaddr,omitempty"` // Broadcast address (if available)
	Dstaddr   string `json:"dstaddr,omitempty"`   // Destination address (if available)
}

// IFace represents a network interface.
type IFace struct {
	Name        string     `json:"name"`                  // Interface name
	Description string     `json:"description,omitempty"` // Description (can be empty)
	Flags       uint32     `json:"flags"`                 // Interface flags
	Addresses   []PcapAddr `json:"addresses"`             // List of addresses associated with the interface
}

// GetIfaceChannel safely retrieves the channel for a specific interface.
func GetIfaceChannel(ifaceName string) <-chan FrameData {
	mapMutex.RLock()
	defer mapMutex.RUnlock()
	return frameDataChanMap[ifaceName]
}

// ParseIFace parses the JSON representation of interface lists.
func ParseIFace(src string) (iFaces []IFace, err error) {
	err = sonic.Unmarshal([]byte(src), &iFaces)
	return
}

// GetIFaces retrieves the list of available network interfaces.
func GetIFaces() (iFaces []IFace, err error) {
	cList := C.get_if_list()
	if cList == nil {
		return nil, errors.New("failed to get interface list from C")
	}
	defer C.free(unsafe.Pointer(cList))

	iFaces, err = ParseIFace(CChar2GoStr(cList))
	return
}

// GetIFaceNonblockStatus checks if a network interface is in non-blocking mode.
func GetIFaceNonblockStatus(interfaceName string) (isNonblock bool, err error) {
	if interfaceName == "" {
		err = errors.Wrap(err, "interface name is blank")
		return
	}

	cName := C.CString(interfaceName)
	defer C.free(unsafe.Pointer(cName))

	nonblockStatus := C.get_if_nonblock_status(cName)
	if nonblockStatus == 0 {
		isNonblock = false
	} else if nonblockStatus == 1 {
		isNonblock = true
	} else {
		err = errors.Wrapf(ErrFromCLogic, "nonblockStatus:%v", nonblockStatus)
	}
	return
}

// SetIFaceNonblockStatus sets the non-blocking mode for a network interface.
func SetIFaceNonblockStatus(interfaceName string, isNonblock bool) (status bool, err error) {
	if interfaceName == "" {
		err = errors.Wrap(err, "interface name is blank")
		return
	}

	cName := C.CString(interfaceName)
	defer C.free(unsafe.Pointer(cName))

	setNonblockCode := 0
	if isNonblock {
		setNonblockCode = 1
	}

	nonblockStatus := C.set_if_nonblock_status(cName, C.int(setNonblockCode))
	if nonblockStatus == 0 {
		status = false
	} else if nonblockStatus == 1 {
		status = true
	} else {
		err = errors.Wrapf(ErrFromCLogic, "nonblockStatus:%v", nonblockStatus)
	}
	return
}

//export GetDataCallback
func GetDataCallback(data *C.char, length C.int, interfaceName *C.char) {
	if data == nil {
		return
	}

	goPacket := C.GoBytes(unsafe.Pointer(data), length)

	interfaceNameStr := ""
	if interfaceName != nil {
		interfaceNameStr = C.GoString(interfaceName)
	}

	frame, err := ParseFrameData(goPacket)
	if err != nil {
		slog.Warn("Error parsing frame data", "err", err)
		return
	}

	// Use safe map access
	mapMutex.RLock()
	ch, ok := frameDataChanMap[interfaceNameStr]
	mapMutex.RUnlock()

	if ok {
		select {
		case ch <- *frame:
		default:
			slog.Warn("Channel full, dropping packet", "interface", interfaceNameStr)
		}
	}
}

// StartLivePacketCapture starts capturing and dissecting packets in real-time.
// This function blocks until the capture finishes or fails.
//
// interfaceName: Network interface name (e.g., "eth0", "en0").
// bpfFilter: BPF filter string (e.g., "tcp port 80").
// packetCount: Number of packets to capture (-1 for infinite).
// promisc: 1 for promiscuous mode, 0 otherwise.
// timeout: Read timeout in milliseconds.
func StartLivePacketCapture(interfaceName, bpfFilter string, packetCount, promisc, timeout int, opts ...Option) (err error) {
	if interfaceName == "" {
		return errors.New("device name is blank")
	}

	// Initialize channel for this interface
	mapMutex.Lock()
	if _, ok := frameDataChanMap[interfaceName]; ok {
		mapMutex.Unlock()
		return errors.Errorf("capture already running on %s", interfaceName)
	}
	frameDataChanMap[interfaceName] = make(chan FrameData, 1000)
	mapMutex.Unlock()

	conf := NewConfig(opts...)
	printCJson := 0
	if conf.PrintCJson {
		printCJson = 1
	}

	cIfName := C.CString(interfaceName)
	cBpf := C.CString(bpfFilter)
	cConf := C.CString(HandleConf(conf))
	defer func() {
		C.free(unsafe.Pointer(cIfName))
		C.free(unsafe.Pointer(cBpf))
		C.free(unsafe.Pointer(cConf))
	}()

	// This call blocks
	errMsg := C.handle_packet(cIfName, cBpf, C.int(packetCount),
		C.int(promisc), C.int(timeout), C.int(printCJson), cConf)

	if C.strlen(errMsg) != 0 {
		// Cleanup on failure
		mapMutex.Lock()
		delete(frameDataChanMap, interfaceName)
		mapMutex.Unlock()
		return errors.Errorf("fail to capture packet live: %s", CChar2GoStr(errMsg))
	}

	return nil
}

// StopLivePacketCapture sends a signal to stop the capture loop for the given interface.
func StopLivePacketCapture(interfaceName string) (err error) {
	if interfaceName == "" {
		return errors.New("device name is blank")
	}

	cIfName := C.CString(interfaceName)
	defer C.free(unsafe.Pointer(cIfName))

	errMsg := C.stop_dissect_capture_pkg(cIfName)
	if C.strlen(errMsg) != 0 {
		return errors.Errorf("fail to stop capture packet live: %s", CChar2GoStr(errMsg))
	}

	// Cleanup channel safely
	mapMutex.Lock()
	if ch, ok := frameDataChanMap[interfaceName]; ok {
		close(ch)
		delete(frameDataChanMap, interfaceName)
	}
	mapMutex.Unlock()

	return nil
}
