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
	"time"

	"github.com/pkg/errors"
)

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

// UnmarshalIFace Unmarshal interface device
func UnmarshalIFace(src string) (iFaces []IFace, err error) {
	err = json.Unmarshal([]byte(src), &iFaces)
	if err != nil {
		return
	}

	return iFaces, nil
}

// GetIfaceList Get interface list
func GetIfaceList() (iFaces []IFace, err error) {
	iFaces, err = UnmarshalIFace(CChar2GoStr(C.get_if_list()))
	if err != nil {
		return
	}

	return iFaces, nil
}

// GetIfaceNonblockStatus Get interface nonblock status
func GetIfaceNonblockStatus(deviceName string) (isNonblock bool, err error) {
	if deviceName == "" {
		err = errors.Wrap(err, "device name is blank")
		return
	}

	nonblockStatus := C.get_if_nonblock_status(C.CString(deviceName))
	if nonblockStatus == 0 {
		isNonblock = false
	} else if nonblockStatus == 1 {
		isNonblock = true
	} else {
		err = errors.Wrapf(ErrFromCLogic, "nonblockStatus:%v", nonblockStatus)
	}

	return
}

// SetIfaceNonblockStatus Set interface nonblock status
func SetIfaceNonblockStatus(deviceName string, isNonblock bool) (status bool, err error) {
	if deviceName == "" {
		err = errors.Wrap(err, "device name is blank")
		return
	}

	setNonblockCode := 0
	if isNonblock {
		setNonblockCode = 1
	}

	nonblockStatus := C.set_if_nonblock_status(C.CString(deviceName), C.int(setNonblockCode))
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
func GetDataCallback(data *C.char, length C.int, deviceName *C.char) {
	goPacket := ""
	if data != nil {
		goPacket = C.GoStringN(data, length)
	}

	deviceNameStr := ""
	if deviceName != nil {
		deviceNameStr = C.GoString(deviceName)
	}

	// unmarshal each pkg dissect result
	singleFrameRes, err := UnmarshalDissectResult(goPacket)
	if err != nil {
		slog.Warn("Error:", "UnmarshalDissectResult", err, "WsIndex", singleFrameRes.WsIndex)
	}

	// write packet dissect result to go pipe
	if ch, ok := DissectResChans[deviceNameStr]; ok {
		ch <- *singleFrameRes
	}
}

// DissectPktLive
//
//	@Description: Set up callback function, capture and dissect packet.
//	@param deviceName
//	@param bpfFilter bpf filter
//	@param num
//	@param promisc: 0 indicates a non-promiscuous mode, and any other value indicates a promiscuous mode
//	@param timeout
func DissectPktLive(deviceName, bpfFilter string, num, promisc, timeout int, opts ...Option) (err error) {
	// Set up callback function
	C.setDataCallback((C.DataCallback)(C.GetDataCallback))

	if deviceName == "" {
		err = errors.Wrap(err, "device name is blank")
		return
	}

	conf := NewConfig(opts...)
	descriptive := 0
	if conf.Descriptive {
		descriptive = 1
	}

	printCJson := 0
	if conf.PrintCJson {
		printCJson = 1
	}

	errMsg := C.handle_packet(C.CString(deviceName), C.CString(bpfFilter), C.int(num), C.int(promisc), C.int(timeout),
		C.int(descriptive), C.int(printCJson), C.CString(HandleConf(conf)))
	if C.strlen(errMsg) != 0 {
		// transfer c char to go string
		errMsgStr := CChar2GoStr(errMsg)
		err = errors.Errorf("fail to capture packet live:%s", errMsgStr)
		return
	}

	return
}

// StopDissectPktLive Stop capture packet live、 free all memory allocated.
func StopDissectPktLive(deviceName string) (err error) {
	if deviceName == "" {
		err = errors.Wrap(err, "device name is blank")
		return
	}

	errMsg := C.stop_dissect_capture_pkg(C.CString(deviceName))
	if C.strlen(errMsg) != 0 {
		// transfer c char to go string
		errMsgStr := CChar2GoStr(errMsg)
		err = errors.Errorf("fail to stop capture packet live:%s", errMsgStr)
		return
	}

	return
}

// TimeEpoch2Time turn wireshark timestamp to time.Time
func TimeEpoch2Time(wiresharkTimestamp float64) (goTime time.Time) {
	seconds := int64(wiresharkTimestamp)
	microseconds := int64((wiresharkTimestamp - float64(seconds)) * 1e6)
	return time.Unix(seconds, microseconds*1000)
}
