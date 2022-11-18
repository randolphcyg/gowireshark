package gowireshark

/*
#cgo pkg-config: glib-2.0
#cgo LDFLAGS: -L${SRCDIR}/libs -lwiretap -lwsutil -lwireshark -lpcap
#cgo LDFLAGS: -Wl,-rpath,${SRCDIR}/libs
#cgo CFLAGS: -I${SRCDIR}/include/wireshark
#cgo CFLAGS: -I${SRCDIR}/include/libpcap

#include <cfile.h>
#include <epan/charsets.h>
#include <epan/column.h>
#include <epan/epan.h>
#include <epan/epan_dissect.h>
#include <epan/frame_data.h>
#include <epan/frame_data_sequence.h>
#include <epan/print.h>
#include <epan/print_stream.h>
#include <epan/print_stream.h>
#include <epan/tap.h>
#include <epan/tvbuff.h>
#include <include/cJSON.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <wiretap/wtap-int.h>
#include <wiretap/wtap.h>
#include <wsutil/json_dumper.h>
#include <wsutil/nstime.h>
#include <wsutil/privileges.h>
#include <epan/tap.h>
// Init policies、wtap mod、epan mod.
int init_env();
// Init capture file
int init_cf(char *filename);
// Read each frame
gboolean read_packet(epan_dissect_t **edt_r);
// Dissect and print all frames
void print_all_frame();
// Dissect and print the first frame
void print_first_frame();
// Dissect and print the first several frames
void print_first_several_frame(int count);
// Dissect and print specific frame
int print_specific_frame(int num);
// Dissect and get hex data of specific frame
char *get_specific_frame_hex_data(int num);
// Get proto tree in json format
char *proto_tree_in_json(int num);
// Get interface list
char *get_if_list();
// Get interface nonblock status
int get_if_nonblock_status(char *device_name);
// Set interface nonblock status
int set_if_nonblock_status(char *device_name, int nonblock);
// Capture and dissect packet in real time
int handle_pkt_live(char *device_name, int num);
*/
import "C"
import (
	"encoding/json"
	"os"
	"reflect"
	"strconv"
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

func init() {
	// Init policies、wtap mod、epan mod.
	initEnvRes := C.init_env()
	if initEnvRes == 0 {
		panic("init env failed")
	}
}

// isFileExist check if the file path exists
func isFileExist(path string) bool {
	_, err := os.Lstat(path)
	return !os.IsNotExist(err)
}

// CChar2GoStr C string -> Go string
func CChar2GoStr(src *C.char) (res string) {
	var s0 string
	var s0Hdr = (*reflect.StringHeader)(unsafe.Pointer(&s0))
	s0Hdr.Data = uintptr(unsafe.Pointer(src))
	s0Hdr.Len = int(C.strlen(src))

	sLen := int(C.strlen(src))
	s1 := string((*[SINGLEPKTMAXLEN]byte)(unsafe.Pointer(src))[:sLen:sLen])

	return s1
}

// EpanVersion get epan module's version
func EpanVersion() string {
	return C.GoString((*C.char)(C.epan_get_version()))
}

// EpanPluginsSupported
/** Returns_
 *     0 if plugins can be loaded for all of libwireshark (tap, dissector, epan).
 *     1 if plugins are not supported by the platform.
 *    -1 if plugins were disabled in the build configuration.
 */
func EpanPluginsSupported() int {
	return int(C.epan_plugins_supported())
}

// initCapFile Init capture file only once for each pcap file
func initCapFile(inputFilepath string) (err error) {
	if !isFileExist(inputFilepath) {
		err = errors.Wrap(ErrFileNotFound, inputFilepath)
		return
	}

	errNo := C.init_cf(C.CString(inputFilepath))
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

// DissectPrintFirstSeveralFrame Dissect and print the first several frames
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

// DissectPrintSpecificFrame Dissect and print the Specific frame
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

	// transfer c char to go string
	srcHexStr := CChar2GoStr(srcHex)

	// unmarshal dissect result
	hexData, err = UnmarshalHexData(srcHexStr)
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

// GetSpecificFrameProtoTreeInJson Transfer specific frame proto tree to json format
func GetSpecificFrameProtoTreeInJson(inputFilepath string, num int) (allFrameDissectRes map[string]FrameDissectRes, err error) {
	err = initCapFile(inputFilepath)
	if err != nil {
		return
	}

	counter := 0
	allFrameDissectRes = make(map[string]FrameDissectRes)
	for {
		counter++
		if counter < num && num != counter {
			continue
		}

		// get proto dissect result in json format by c
		srcFrame := C.proto_tree_in_json(C.int(counter))
		if srcFrame != nil {
			if C.strlen(srcFrame) == 0 {
				break
			}
		}

		// transfer c char to go string
		srcFrameStr := CChar2GoStr(srcFrame)

		// unmarshal dissect result
		singleFrameData, err := UnmarshalDissectResult(srcFrameStr)
		if err != nil {
			err = errors.Wrap(ErrUnmarshalObj, "Frame num "+strconv.Itoa(counter))
			break
		}
		allFrameDissectRes[strconv.Itoa(counter)] = singleFrameData

		break
	}

	return
}

// GetAllFrameProtoTreeInJson Transfer proto tree to json format
func GetAllFrameProtoTreeInJson(inputFilepath string) (allFrameDissectRes map[string]FrameDissectRes, err error) {
	err = initCapFile(inputFilepath)
	if err != nil {
		return
	}

	counter := 1
	allFrameDissectRes = make(map[string]FrameDissectRes)
	for {
		// get proto dissect result in json format by c
		srcFrame := C.proto_tree_in_json(C.int(counter))
		if srcFrame != nil {
			if C.strlen(srcFrame) == 0 { // loop ends
				break
			}
		}

		// transfer c char to go string
		srcFrameStr := CChar2GoStr(srcFrame)

		// unmarshal dissect result
		singleFrameData, err := UnmarshalDissectResult(srcFrameStr)
		if err != nil {
			err = errors.Wrap(ErrUnmarshalObj, "Frame num "+strconv.Itoa(counter))
			break
		}
		allFrameDissectRes[strconv.Itoa(counter)] = singleFrameData
		counter++
	}

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
	src := C.get_if_list()
	// transfer c char to go string
	// unmarshal interface device list obj
	res, err = UnmarshalIFace(CChar2GoStr(src))
	if err != nil {
		err = ErrUnmarshalObj
		return
	}

	return
}

// GetIfaceNonblockStatus Get interface nonblock status
func GetIfaceNonblockStatus(deviceName string) (isNonblock bool, err error) {
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

// DissectPktLive Capture packet by libpcap and dissect each one by wireshark
// TODO 1. There are still deviations in the parsing results of the protocol tree, and all four layers are put into data
// 1. How Go efficiently obtains parsing results from C's callback function
func DissectPktLive(deviceName string, num int) error {

	C.handle_pkt_live(C.CString(deviceName), C.int(num))

	return nil
}
