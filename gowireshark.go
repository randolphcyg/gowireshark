package gowireshark

/*
#cgo pkg-config: glib-2.0
#cgo LDFLAGS: -L${SRCDIR}/libs -lwiretap -lwsutil -lwireshark
#cgo LDFLAGS: -Wl,-rpath,${SRCDIR}/libs
#cgo CFLAGS: -I${SRCDIR}/include/wireshark
#cgo CFLAGS: -std=c99

#include <include/lib.h>
#include <cfile.h>
#include <epan/charsets.h>
#include <epan/column.h>
#include <epan/epan.h>
#include <epan/epan_dissect.h>
#include <epan/frame_data.h>
#include <epan/frame_data_sequence.h>
#include <epan/print.h>
#include <epan/print_stream.h>
#include <epan/tvbuff.h>
#include <include/cJSON.h>
#include <stdio.h>
#include <wiretap/wtap-int.h>
#include <wiretap/wtap.h>
#include <wsutil/json_dumper.h>
#include <wsutil/nstime.h>
#include <wsutil/privileges.h>
// Init modules & Init capture_file
int init(char *filename);
// Read each frame
gboolean read_packet(epan_dissect_t **edt_r);
// Dissect and print all frames
void print_all_frame();
// Dissect and print the first frame
void print_first_frame();
// Dissect and print the first several frames
void print_first_several_frame(int count);
// Dissect and print specific frame
void print_specific_frame(int num);
// Dissect and get hex data of specific frame
char *get_specific_frame_hex_data(int num);
// Get proto tree in json format
char *proto_tree_in_json(int num);
*/
import "C"
import (
	"encoding/json"
	"reflect"
	"strconv"
	"unsafe"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/randolphcyg/gowireshark/common/middleware/logger"
	"github.com/randolphcyg/gowireshark/common/tool"
)

var (
	ErrFileNotFound           = errors.New("cannot open file, no such file")
	ErrReadFile               = errors.New("occur error when read file ")
	ErrIllegalPara            = errors.New("illegal parameter")
	WarnFrameIndexOutOfBounds = errors.New("frame index is out of bounds")
	ErrUnmarshalDissectResult = errors.New("unmarshal dissect result error")
	ErrEmptyDissectResult     = errors.New("proto dissect result is empty by c")
)

// SINGLEPKTMAXLEN The maximum length limit of the json object of the parsing
// result of a single data packet, which is convenient for converting c char to go string
const SINGLEPKTMAXLEN = 65535

func init() {
	// init logger
	logger.Init()
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

// initCapFile Init capture file only once
func initCapFile(inputFilepath string) (err error) {
	if !tool.IsFileExist(inputFilepath) {
		err = errors.Wrap(ErrFileNotFound, inputFilepath)
		log.Error(err)
		return
	}

	errNo := C.init(C.CString(inputFilepath))
	if errNo != 0 {
		err = errors.Wrap(ErrReadFile, strconv.Itoa(int(errNo)))
		log.Error(err)
		return
	}

	return
}

// DissectPrintFirstFrame Dissect and print the first frame
func DissectPrintFirstFrame(inputFilepath string) (err error) {
	err = initCapFile(inputFilepath)
	if err != nil {
		log.Error(err)
		return
	}

	C.print_first_frame()

	return
}

// DissectPrintAllFrame Dissect and print all frames
func DissectPrintAllFrame(inputFilepath string) (err error) {
	err = initCapFile(inputFilepath)
	if err != nil {
		log.Error(err)
		return
	}

	C.print_all_frame()

	return
}

// DissectPrintFirstSeveralFrame Dissect and print the first several frames
func DissectPrintFirstSeveralFrame(inputFilepath string, count int) (err error) {
	err = initCapFile(inputFilepath)
	if err != nil {
		log.Error(err)
		return
	}

	if count < 1 {
		err = errors.Wrap(ErrIllegalPara, strconv.Itoa(count))
		log.Error(err)
		return
	}

	C.print_first_several_frame(C.int(count))

	return
}

// DissectSpecificFrameByGo Dissect and print the Specific frame
// [by call read_packet with cgo, can judge the bounds of frame ]
func DissectSpecificFrameByGo(inputFilepath string, num int) (err error) {
	err = initCapFile(inputFilepath)
	if err != nil {
		log.Error(err)
		return
	}

	if num < 1 {
		err = errors.Wrap(ErrIllegalPara, strconv.Itoa(num))
		log.Error(err)
		return
	}

	// start reading packets
	count := 0
	var edt *C.struct_epan_dissect
	print_stream := C.print_stream_text_stdio_new(C.stdout)
	for {
		success := C.read_packet(&edt)
		if success == 1 {
			count++
			if count < num && num != count {
				C.epan_dissect_free(edt)
				edt = nil
				continue
			}

			// print proto tree
			C.proto_tree_print(C.print_dissections_expanded, 0, edt, nil, print_stream)
			// print hex data
			C.print_hex_data(print_stream, edt)

			C.epan_dissect_free(edt)
			edt = nil

			break
		}

		err = errors.Wrap(WarnFrameIndexOutOfBounds, "Frame num "+strconv.Itoa(num))
		log.Warn(err)

		return
	}

	return
}

// DissectPrintSpecificFrame Dissect and print the Specific frame
func DissectPrintSpecificFrame(inputFilepath string, num int) (err error) {
	err = initCapFile(inputFilepath)
	if err != nil {
		log.Error(err)
		return
	}

	if num < 1 {
		err = errors.Wrap(ErrIllegalPara, "Frame num "+strconv.Itoa(num))
		log.Error(err)
		return
	}

	// print none if num is out of bounds
	C.print_specific_frame(C.int(num))

	return
}

// DissectSpecificFrameHexData Dissect and print hex_data of specific frame
func DissectSpecificFrameHexData(inputFilepath string, num int) (err error) {
	err = initCapFile(inputFilepath)
	if err != nil {
		log.Error(err)
		return
	}

	if num < 1 {
		err = errors.Wrap(ErrIllegalPara, "Frame num "+strconv.Itoa(num))
		log.Error(err)
		return
	}

	// print none if num is out of bounds
	C.get_specific_frame_hex_data(C.int(num))

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
		log.Error(err)
		return
	}

	// get specific frame hex data in json format by c
	srcHex := C.get_specific_frame_hex_data(C.int(num))
	if srcHex != nil {
		if C.strlen(srcHex) == 0 {
			err = errors.Wrap(ErrIllegalPara, "Frame num "+strconv.Itoa(num))
			log.Error(err)
			return
		}
	}

	// transfer c char to go string
	srcHexStr := CChar2GoStr(srcHex)

	// unmarshal dissect result
	hexData, err = UnmarshalHexData(srcHexStr)
	if err != nil {
		err = errors.Wrap(ErrUnmarshalDissectResult, "Frame num "+strconv.Itoa(num))
		log.Error(err)
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
		log.Error(err)
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
				err = errors.Wrap(ErrIllegalPara, "Frame num "+strconv.Itoa(num))
				log.Error(err)
				break
			}
		}

		// transfer c char to go string
		srcFrameStr := CChar2GoStr(srcFrame)

		// unmarshal dissect result
		singleFrameData, err := UnmarshalDissectResult(srcFrameStr)
		if err != nil {
			err = errors.Wrap(ErrUnmarshalDissectResult, "Frame num "+strconv.Itoa(counter))
			log.Error(err)
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
		log.Error(err)
		return
	}

	counter := 1
	allFrameDissectRes = make(map[string]FrameDissectRes)
	for {
		// get proto dissect result in json format by c
		srcFrame := C.proto_tree_in_json(C.int(counter))
		if srcFrame != nil {
			if C.strlen(srcFrame) == 0 {
				err = errors.Wrap(ErrIllegalPara, "Frame num "+strconv.Itoa(counter))
				log.Error(err)
				break
			}
		}

		// transfer c char to go string
		srcFrameStr := CChar2GoStr(srcFrame)

		// unmarshal dissect result
		singleFrameData, err := UnmarshalDissectResult(srcFrameStr)
		if err != nil {
			err = errors.Wrap(ErrUnmarshalDissectResult, "Frame num "+strconv.Itoa(counter))
			log.Error(err)
			break
		}
		allFrameDissectRes[strconv.Itoa(counter)] = singleFrameData
		counter++
	}

	return
}
