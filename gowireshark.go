package gowireshark

/*
#cgo pkg-config: glib-2.0
#cgo LDFLAGS: -Wl,-rpath,${SRCDIR}/libs
#cgo LDFLAGS: -L${SRCDIR}/libs -lwiretap -lwsutil -lwireshark -lpcap
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
	"fmt"
	"net"
	"os"
	"strconv"
	"syscall"
	"unsafe"

	"github.com/pkg/errors"
)

var (
	ErrFileNotFound           = errors.New("cannot open file, no such file")
	ErrReadFile               = errors.New("occur error when read file ")
	ErrIllegalPara            = errors.New("illegal parameter")
	WarnFrameIndexOutOfBounds = errors.New("frame index is out of bounds")
	ErrUnmarshalObj           = errors.New("unmarshal obj error")
	ErrFromCLogic             = errors.New("run c logic occur error")
)

// SINGLEPKTMAXLEN The maximum length limit of the json object of the parsing
// result of a single data packet, which is convenient for converting c char to go string
const SINGLEPKTMAXLEN = 6553500

// Init policies、WTAP mod、EPAN mod.
func init() {
	initEnvRes := C.init_env()
	if initEnvRes == 0 {
		panic("fail to init env")
	}
}

// isFileExist check if the file path exists
func isFileExist(path string) bool {
	_, err := os.Lstat(path)
	return !os.IsNotExist(err)
}

// CChar2GoStr C string -> Go string
func CChar2GoStr(src *C.char) string {
	sLen := int(C.strlen(src))
	return string((*[SINGLEPKTMAXLEN]byte)(unsafe.Pointer(src))[:sLen:sLen])
}

// EpanVersion get epan module's version
func EpanVersion() string {
	return C.GoString((*C.char)(C.epan_get_version()))
}

// EpanPluginsSupported
//
//	@Description:
//	@return int: 0 if plugins can be loaded for all of libwireshark (tap, dissector, epan);
//	1 if plugins are not supported by the platform;
//	-1 if plugins were disabled in the build configuration.
func EpanPluginsSupported() int {
	return int(C.epan_plugins_supported())
}

// initCapFile Init capture file only once for each pcap file
func initCapFile(inputFilepath string) (err error) {
	if !isFileExist(inputFilepath) {
		err = errors.Wrap(ErrFileNotFound, inputFilepath)
		return
	}

	inputFilepathCStr := C.CString(inputFilepath)
	errNo := C.init_cf(inputFilepathCStr)
	if errNo != 0 {
		err = errors.Wrap(ErrReadFile, strconv.Itoa(int(errNo)))
		return
	}

	return
}

// DissectPrintFirstFrame Dissect and print the first frame
func DissectPrintFirstFrame(inputFilepath string) (err error) {
	err = initCapFile(inputFilepath)
	if err != nil {
		return
	}

	C.print_first_frame()

	return
}

// DissectPrintAllFrame Dissect and print all frames
func DissectPrintAllFrame(inputFilepath string) (err error) {
	err = initCapFile(inputFilepath)
	if err != nil {
		return
	}

	C.print_all_frame()

	return
}

// DissectPrintFirstSeveralFrame
//
//	@Description: Dissect and print the first several frames
//	@param inputFilepath: Pcap src file path
//	@param count: The index of the first several frame you want to dissect
func DissectPrintFirstSeveralFrame(inputFilepath string, count int) (err error) {
	err = initCapFile(inputFilepath)
	if err != nil {
		return
	}

	if count < 1 {
		err = errors.Wrap(ErrIllegalPara, strconv.Itoa(count))
		return
	}

	C.print_first_several_frame(C.int(count))

	return
}

// DissectPrintSpecificFrame
//
//	@Description: Dissect and print the Specific frame
//	@param inputFilepath: Pcap src file path
//	@param num: The index value of the specific frame you want to dissect
func DissectPrintSpecificFrame(inputFilepath string, num int) (err error) {
	err = initCapFile(inputFilepath)
	if err != nil {
		return
	}

	if num < 1 {
		err = errors.Wrap(ErrIllegalPara, "Frame num "+strconv.Itoa(num))
		return
	}

	// errNo is 2 if num is out of bounds
	errNo := C.print_specific_frame(C.int(num))
	if errNo == 2 {
		err = errors.Wrap(WarnFrameIndexOutOfBounds, strconv.Itoa(int(errNo)))
		return
	}

	return
}

// HexData hex data
type HexData struct {
	Offset []string `json:"offset"`
	Hex    []string `json:"hex"`
	Ascii  []string `json:"ascii"`
}

// UnmarshalHexData Unmarshal hex data dissect result
func UnmarshalHexData(src string) (res HexData, err error) {
	err = json.Unmarshal([]byte(src), &res)
	if err != nil {
		return HexData{}, err
	}

	return
}

// GetSpecificFrameHexData Get hex data of specific frame
func GetSpecificFrameHexData(inputFilepath string, num int) (hexData HexData, err error) {
	err = initCapFile(inputFilepath)
	if err != nil {
		return
	}

	// get specific frame hex data in json format by c
	srcHex := C.get_specific_frame_hex_data(C.int(num))
	if srcHex != nil {
		if C.strlen(srcHex) == 0 { // loop ends
			return
		}
	}

	// unmarshal dissect result
	hexData, err = UnmarshalHexData(CChar2GoStr(srcHex))
	if err != nil {
		err = errors.Wrap(ErrUnmarshalObj, "Frame num "+strconv.Itoa(num))
		return
	}

	return
}

// FrameDissectRes Dissect results of each frame of data
type FrameDissectRes struct {
	WsIndex  string   `json:"_index"`
	Offset   []string `json:"offset"`
	Hex      []string `json:"hex"`
	Ascii    []string `json:"ascii"`
	WsSource struct {
		Layers map[string]interface{} `json:"layers"`
	} `json:"_source"`
}

// UnmarshalDissectResult Unmarshal dissect result
func UnmarshalDissectResult(src string) (res FrameDissectRes, err error) {
	err = json.Unmarshal([]byte(src), &res)
	if err != nil {
		return FrameDissectRes{}, err
	}

	return
}

// GetSpecificFrameProtoTreeInJson
//
//	@Description: Transfer specific frame proto tree to json format
//	@param inputFilepath: Pcap src file path
//	@param num: The max frame index value of the JSON results
//	@param isDescriptive: Whether the JSON result has descriptive fields
//	@param isDebug: Whether to print JSON result in C logic
//	@return res: Contains specific frame's JSON dissect result
func GetSpecificFrameProtoTreeInJson(inputFilepath string, num int, isDescriptive, isDebug bool) (res map[string]FrameDissectRes, err error) {
	err = initCapFile(inputFilepath)
	if err != nil {
		return
	}

	descriptive := 0
	if isDescriptive {
		descriptive = 1
	}

	debug := 0
	if isDebug {
		debug = 1
	}

	counter := 0
	res = make(map[string]FrameDissectRes)
	for {
		counter++
		if counter < num && num != counter {
			continue
		}

		// get proto dissect result in json format by c
		srcFrame := C.proto_tree_in_json(C.int(counter), C.int(descriptive), C.int(debug))
		if srcFrame != nil {
			if C.strlen(srcFrame) == 0 {
				break
			}
		}

		// unmarshal dissect result
		singleFrame, err := UnmarshalDissectResult(CChar2GoStr(srcFrame))
		if err != nil {
			err = errors.Wrap(ErrUnmarshalObj, "Frame num "+strconv.Itoa(counter))
			fmt.Println(err)
			break
		}

		res[strconv.Itoa(counter)] = singleFrame

		break
	}

	return
}

// GetAllFrameProtoTreeInJson
//
//	@Description: Transfer proto tree to json format
//	@param inputFilepath: Pcap src file path
//	@param isDescriptive: Whether the JSON result has descriptive fields
//	@param isDebug: Whether to print JSON result in C logic
//	@param ch: Save dissect result one by one
func GetAllFrameProtoTreeInJson(inputFilepath string, isDescriptive bool, isDebug bool, ch chan map[int]FrameDissectRes) (err error) {
	err = initCapFile(inputFilepath)
	if err != nil {
		return
	}

	descriptive := 0
	if isDescriptive {
		descriptive = 1
	}

	debug := 0
	if isDebug {
		debug = 1
	}

	counter := 1
	for {
		// get proto dissect result in json format by c
		srcFrame := C.proto_tree_in_json(C.int(counter), C.int(descriptive), C.int(debug))
		if srcFrame != nil {
			if C.strlen(srcFrame) == 0 { // loop ends
				break
			}
		}

		// unmarshal dissect result
		singleFrame, err := UnmarshalDissectResult(CChar2GoStr(srcFrame))
		if err != nil {
			err = errors.Wrap(ErrUnmarshalObj, "Frame num "+strconv.Itoa(counter))
			fmt.Println(err)
			break
		}

		ch <- map[int]FrameDissectRes{counter: singleFrame}
		counter++
	}

	// close channel
	defer close(ch)

	return
}

// IFace interface device
type IFace struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Flags       int    `json:"flags"`
}

// UnmarshalIFace Unmarshal interface device
func UnmarshalIFace(src string) (res map[string]IFace, err error) {
	err = json.Unmarshal([]byte(src), &res)
	if err != nil {
		return nil, err
	}

	return
}

// GetIfaceList Get interface list
func GetIfaceList() (res map[string]IFace, err error) {
	// unmarshal interface device list obj
	res, err = UnmarshalIFace(CChar2GoStr(C.get_if_list()))
	if err != nil {
		err = ErrUnmarshalObj
		return
	}

	return
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

// RunSock Unix domain socket(AF_UNIX) server: start socket and read data.
func RunSock(sockServerPath string, sockBuffSize int, listener *net.UnixConn, pkgChan chan FrameDissectRes) (err error) {
	if sockServerPath == "" {
		err = errors.Wrap(err, "sockServerPath is blank")
		return
	}

	addr, err := net.ResolveUnixAddr("unixgram", sockServerPath)
	if err != nil {
		err = errors.Wrap(err, "fail to resolve UnixAddr")
		panic(err)
	}

	syscall.Unlink(sockServerPath)
	if listener == nil {
		listener, err = net.ListenUnixgram("unixgram", addr)
		if err != nil {
			err = errors.Wrap(err, "fail to start Unix domain socket(AF_UNIX) server")
			return
		}
	}

	// read data from c client
	go readSock(listener, pkgChan, sockBuffSize)

	return
}

// readSock Unix domain socket(AF_UNIX) server: read data func
func readSock(listener *net.UnixConn, pkgChan chan FrameDissectRes, sockBuffSize int) {
	for {
		buf := make([]byte, sockBuffSize)
		size, _, err := listener.ReadFromUnix(buf)
		if err != nil {
			err = errors.Wrap(err, "fail to read from Unix domain socket(AF_UNIX) client")
			panic(err)
		}

		// handle each pkg
		// unmarshal dissect result
		singleFrameData, err := UnmarshalDissectResult(string(buf[:size]))
		if err != nil {
			err = errors.Wrap(ErrUnmarshalObj, "WsIndex: "+singleFrameData.WsIndex)
			fmt.Println(err)
		}

		// write packet dissect result to go pipe
		pkgChan <- singleFrameData
	}
}

// DissectPktLive
//
//	@Description: Start up Unix domain socket(AF_UNIX) client, capture and dissect packet.
//	@param deviceName
//	@param sockServerPath
//	@param num
//	@param promisc: 0 indicates a non-promiscuous mode, and any other value indicates a promiscuous mode
//	@param timeout
func DissectPktLive(deviceName, sockServerPath string, num, promisc, timeout int) (err error) {
	if deviceName == "" {
		err = errors.Wrap(err, "device name is blank")
		return
	}

	if sockServerPath == "" {
		err = errors.Wrap(err, "sockServerPath is blank")
		return
	}

	errMsg := C.handle_packet(C.CString(deviceName), C.CString(sockServerPath), C.int(num), C.int(promisc), C.int(timeout))
	if C.strlen(errMsg) != 0 {
		// transfer c char to go string
		errMsgStr := CChar2GoStr(errMsg)
		err = errors.Errorf("fail to capture packet live:%s", errMsgStr)
		return
	}

	return
}

// StopDissectPktLive Stop capture packet live、 free all memory allocated、close socket.
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
