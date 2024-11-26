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
	"log/slog"
	"os"
	"slices"
	"strconv"
	"sync"

	"github.com/pkg/errors"
)

var (
	ErrFileNotFound    = errors.New("cannot open file, no such file")
	ErrReadFile        = errors.New("occur error when read file ")
	ErrUnmarshalObj    = errors.New("unmarshal obj error")
	ErrFromCLogic      = errors.New("run c logic occur error")
	ErrParseDissectRes = errors.New("fail to parse DissectRes")
	ErrParseFrame      = errors.New("fail to parse frame")
	ErrFrameIsBlank    = errors.New("frame data is blank")
)

// DissectResChans dissect result chan map
var DissectResChans = make(map[string]chan FrameDissectRes)

var EpanMutex = &sync.Mutex{}

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
	return C.GoStringN(src, C.int(C.strlen(src)))
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
func initCapFile(inputFilepath string, opts ...Option) (conf *Conf, err error) {
	if !isFileExist(inputFilepath) {
		err = errors.Wrap(ErrFileNotFound, inputFilepath)
		return
	}

	conf = NewConfig(opts...)
	errNo := C.init_cf(C.CString(inputFilepath), C.CString(HandleTlsConf(conf)))
	if errNo != 0 {
		err = errors.Wrap(ErrReadFile, strconv.Itoa(int(errNo)))
		return
	}

	return
}

// DissectPrintAllFrame Dissect and print all frames
func DissectPrintAllFrame(inputFilepath string, opts ...Option) (err error) {
	EpanMutex.Lock()
	defer EpanMutex.Unlock()

	_, err = initCapFile(inputFilepath, opts...)
	if err != nil {
		return
	}

	C.print_all_frame()

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
func GetSpecificFrameHexData(inputFilepath string, num int, opts ...Option) (hexData HexData, err error) {
	EpanMutex.Lock()
	defer EpanMutex.Unlock()

	_, err = initCapFile(inputFilepath, opts...)
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

// UnmarshalDissectResult Unmarshal dissect result
func UnmarshalDissectResult(src string) (res FrameDissectRes, err error) {
	err = json.Unmarshal([]byte(src), &res)
	if err != nil {
		return FrameDissectRes{}, ErrParseDissectRes
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
func GetSpecificFrameProtoTreeInJson(inputFilepath string, num int, opts ...Option) (frameDissectRes FrameDissectRes, err error) {
	EpanMutex.Lock()
	defer EpanMutex.Unlock()

	conf, err := initCapFile(inputFilepath, opts...)
	if err != nil {
		return
	}

	descriptive := 0
	if conf.Descriptive {
		descriptive = 1
	}

	debug := 0
	if conf.Debug {
		debug = 1
	}

	counter := 0
	for {
		counter++
		if counter < num && num != counter {
			continue
		}

		// get proto dissect result in json format by c
		srcFrame := C.proto_tree_in_json(C.int(counter), C.int(descriptive), C.int(debug))
		if srcFrame != nil {
			if C.strlen(srcFrame) == 0 {
				return frameDissectRes, ErrFrameIsBlank
			}
		}

		// unmarshal dissect result
		frameDissectRes, err = UnmarshalDissectResult(CChar2GoStr(srcFrame))
		if err != nil {
			err = errors.Wrap(ErrUnmarshalObj, "Counter "+strconv.Itoa(counter))
			return
		}

		return
	}
}

func removeNegativeAndZero(nums []int) []int {
	var result []int
	for _, num := range nums {
		if num > 0 {
			result = append(result, num)
		}
	}
	return result
}

// GetSeveralFrameProtoTreeInJson
//
//	@Description: Transfer specific frame proto tree to json format
//	@param inputFilepath: Pcap src file path
//	@param nums: The frame number that needs to be output
//	@param isDescriptive: Whether the JSON result has descriptive fields
//	@param isDebug: Whether to print JSON result in C logic
//	@return res: Contains specific frame's JSON dissect result
func GetSeveralFrameProtoTreeInJson(inputFilepath string, nums []int, opts ...Option) (res []FrameDissectRes, err error) {
	EpanMutex.Lock()
	defer EpanMutex.Unlock()

	conf, err := initCapFile(inputFilepath, opts...)
	if err != nil {
		return
	}

	descriptive := 0
	if conf.Descriptive {
		descriptive = 1
	}

	debug := 0
	if conf.Debug {
		debug = 1
	}

	nums = removeNegativeAndZero(nums)
	// Must sort from smallest to largest
	slices.Sort(nums)

	for _, num := range nums {
		// get proto dissect result in json format by c
		srcFrame := C.proto_tree_in_json(C.int(num), C.int(descriptive), C.int(debug))
		if srcFrame != nil {
			if C.strlen(srcFrame) == 0 {
				continue
			}
		}

		// unmarshal dissect result
		singleFrame, err := UnmarshalDissectResult(CChar2GoStr(srcFrame))
		if err != nil {
			err = errors.Wrap(ErrUnmarshalObj, "Num "+strconv.Itoa(num))
			slog.Warn(err.Error())
		}

		res = append(res, singleFrame)
	}

	return
}

// GetAllFrameProtoTreeInJson
//
//	@Description: Transfer proto tree to json format
//	@param inputFilepath: Pcap src file path
//	@param isDescriptive: Whether the JSON result has descriptive fields
//	@param isDebug: Whether to print JSON result in C logic
//	@return res: Contains all frame's JSON dissect result
func GetAllFrameProtoTreeInJson(inputFilepath string, opts ...Option) (res []FrameDissectRes, err error) {
	EpanMutex.Lock()
	defer EpanMutex.Unlock()

	conf, err := initCapFile(inputFilepath, opts...)
	if err != nil {
		return
	}

	descriptive := 0
	if conf.Descriptive {
		descriptive = 1
	}

	debug := 0
	if conf.Debug {
		debug = 1
	}

	counter := 1
	for {
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
			err = errors.Wrap(ErrUnmarshalObj, "Counter "+strconv.Itoa(counter))
			slog.Warn(err.Error())
		}

		res = append(res, singleFrame)
		counter++
	}

	return
}
