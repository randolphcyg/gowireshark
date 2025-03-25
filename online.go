package gowireshark

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
	"encoding/json"
	"log/slog"

	"github.com/pkg/errors"
)

// FrameDataChan dissect result chan map
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

// ParseIFace Unmarshal interface device
func ParseIFace(src string) (iFaces []IFace, err error) {
	err = json.Unmarshal([]byte(src), &iFaces)
	if err != nil {
		return
	}

	return iFaces, nil
}

// GetIFaces Get interface list
func GetIFaces() (iFaces []IFace, err error) {
	iFaces, err = ParseIFace(CChar2GoStr(C.get_if_list()))
	if err != nil {
		return
	}

	return iFaces, nil
}

// GetIFaceNonblockStatus
//
// @Description: Check if a network interface is in non-blocking mode.
// @param interfaceName: Name of the network interface.
// @return isNonblock: True if the interface is in non-blocking mode, false otherwise.
func GetIFaceNonblockStatus(interfaceName string) (isNonblock bool, err error) {
	if interfaceName == "" {
		err = errors.Wrap(err, "interface name is blank")
		return
	}

	nonblockStatus := C.get_if_nonblock_status(C.CString(interfaceName))
	if nonblockStatus == 0 {
		isNonblock = false
	} else if nonblockStatus == 1 {
		isNonblock = true
	} else {
		err = errors.Wrapf(ErrFromCLogic, "nonblockStatus:%v", nonblockStatus)
	}

	return
}

// SetIFaceNonblockStatus Set interface nonblock status
func SetIFaceNonblockStatus(interfaceName string, isNonblock bool) (status bool, err error) {
	if interfaceName == "" {
		err = errors.Wrap(err, "interface name is blank")
		return
	}

	setNonblockCode := 0
	if isNonblock {
		setNonblockCode = 1
	}

	nonblockStatus := C.set_if_nonblock_status(C.CString(interfaceName), C.int(setNonblockCode))
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
	goPacket := ""
	if data != nil {
		goPacket = C.GoStringN(data, length)
	}

	interfaceNameStr := ""
	if interfaceName != nil {
		interfaceNameStr = C.GoString(interfaceName)
	}

	// unmarshal each pkg dissect result
	frame, err := ParseFrameData(goPacket)
	if err != nil {
		slog.Warn("Error:", "ParseFrameData", err)
		if frame != nil {
			slog.Warn("Error:", "WsIndex", frame.Index)
		}
		return
	}

	if frame == nil {
		slog.Warn("Error: ParseFrameData returned nil result")
		return
	}

	// write packet dissect result to go pipe
	if ch, ok := FrameDataChan[interfaceNameStr]; ok {
		ch <- *frame
	} else {
		slog.Warn("Error: No channel found for interface", "interfaceName", interfaceNameStr)
	}
}

// StartLivePacketCapture
//
// @Description: Set up a callback function, capture and dissect packets in real-time.
// @param interfaceName: Name of the network interface to capture packets from.
// @param bpfFilter: BPF filter expression to apply to the capture.
// @param packetCount: Number of packets to capture (0 for unlimited).
// @param promisc: 0 for non-promiscuous mode, any other value for promiscuous mode.
// @param timeout: Timeout for the capture operation in milliseconds.
// @param opts: Optional configuration for the capture.
func StartLivePacketCapture(interfaceName, bpfFilter string, packetCount, promisc, timeout int, opts ...Option) (err error) {
	// Set up callback function
	C.setDataCallback((C.DataCallback)(C.GetDataCallback))

	if interfaceName == "" {
		err = errors.Wrap(err, "device name is blank")
		return
	}

	conf := NewConfig(opts...)

	printCJson := 0
	if conf.PrintCJson {
		printCJson = 1
	}

	errMsg := C.handle_packet(C.CString(interfaceName), C.CString(bpfFilter), C.int(packetCount),
		C.int(promisc), C.int(timeout), C.int(printCJson), C.CString(HandleConf(conf)))
	if C.strlen(errMsg) != 0 {
		err = errors.Errorf("fail to capture packet live:%s", CChar2GoStr(errMsg))
		return
	}

	return
}

// StopLivePacketCapture
//
// @Description: Stop the live packet capture and free all allocated memory.
// @param interfaceName: Name of the network interface to stop capturing from.
func StopLivePacketCapture(interfaceName string) (err error) {
	if interfaceName == "" {
		err = errors.Wrap(err, "device name is blank")
		return
	}

	errMsg := C.stop_dissect_capture_pkg(C.CString(interfaceName))
	if C.strlen(errMsg) != 0 {
		err = errors.Errorf("fail to stop capture packet live:%s", CChar2GoStr(errMsg))
		return
	}

	return
}
