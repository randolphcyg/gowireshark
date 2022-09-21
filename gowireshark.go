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
// init modules & init capture_file
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
// transfer proto tree to json format
char *json_tree(int num);
// Dissect and print hex_data of specific frame
char *print_specific_frame_hex_data(int num);
// inner func
gboolean get_hex_data(epan_dissect_t *edt, cJSON *cjson_offset,
                      cJSON *cjson_hex, cJSON *cjson_ascii);
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
)

// SINGLEPKTMAXLEN The maximum length limit of the json object of the parsing
// result of a single data packet, which is convenient for converting c char to go string
const SINGLEPKTMAXLEN = 65535

func init() {
	// init logger
	logger.Init()
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

// DissectAllFrame Dissect and print all frames
func DissectAllFrame(filepath string) (err error) {
	if !tool.IsFileExist(filepath) {
		err = errors.Wrap(ErrFileNotFound, filepath)
		log.Error(err)
		return
	}

	if errNo := C.init(C.CString(filepath)); errNo != 0 {
		err = errors.Wrap(ErrReadFile, strconv.Itoa(int(errNo)))
		log.Error(err)
		return
	}

	C.print_all_frame()

	return
}

// DissectFirstFrame Dissect and print the first frame
func DissectFirstFrame(filepath string) (err error) {
	if !tool.IsFileExist(filepath) {
		err = errors.Wrap(ErrFileNotFound, filepath)
		log.Error(err)
		return
	}

	if errNo := C.init(C.CString(filepath)); errNo != 0 {
		err = errors.Wrap(ErrReadFile, strconv.Itoa(int(errNo)))
		log.Error(err)
		return
	}

	C.print_first_frame()

	return
}

// DissectFirstSeveralFrame Dissect and print the first several frames
func DissectFirstSeveralFrame(filepath string, count int) (err error) {
	if !tool.IsFileExist(filepath) {
		err = errors.Wrap(ErrFileNotFound, filepath)
		log.Error(err)
		return
	}

	if count < 1 {
		err = errors.Wrap(ErrIllegalPara, strconv.Itoa(count))
		log.Error(err)
		return
	}

	if errNo := C.init(C.CString(filepath)); errNo != 0 {
		err = errors.Wrap(ErrReadFile, strconv.Itoa(int(errNo)))
		log.Error(err)
		return
	}

	C.print_first_several_frame(C.int(count))

	return
}

// DissectSpecificFrameByGo Dissect and print the Specific frame
// [by call read_packet with cgo, can judge the bounds of frame ]
func DissectSpecificFrameByGo(filepath string, num int) (err error) {
	if !tool.IsFileExist(filepath) {
		err = errors.Wrap(ErrFileNotFound, filepath)
		log.Error(err)
		return
	}

	if num < 1 {
		err = errors.Wrap(ErrIllegalPara, strconv.Itoa(num))
		log.Error(err)
		return
	}

	errNo := C.init(C.CString(filepath))
	if errNo != 0 {
		err = errors.Wrap(ErrReadFile, strconv.Itoa(int(errNo)))
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

		err = errors.Wrap(WarnFrameIndexOutOfBounds, strconv.Itoa(num))
		log.Warn(err)

		return
	}

	return
}

// DissectSpecificFrame Dissect and print the Specific frame
func DissectSpecificFrame(filepath string, num int) (err error) {
	if !tool.IsFileExist(filepath) {
		err = errors.Wrap(ErrFileNotFound, filepath)
		log.Error(err)
		return
	}

	if num < 1 {
		err = errors.Wrap(ErrIllegalPara, strconv.Itoa(num))
		log.Error(err)
		return
	}

	errNo := C.init(C.CString(filepath))
	if errNo != 0 {
		err = errors.Wrap(ErrReadFile, strconv.Itoa(int(errNo)))
		log.Error(err)
		return
	}

	// print none if num is out of bounds
	C.print_specific_frame(C.int(num))

	return
}

// DissectSpecificFrameHexData Dissect and print hex_data of specific frame
func DissectSpecificFrameHexData(filepath string, num int) (err error) {
	if !tool.IsFileExist(filepath) {
		err = errors.Wrap(ErrFileNotFound, filepath)
		log.Error(err)
		return
	}

	if num < 1 {
		err = errors.Wrap(ErrIllegalPara, strconv.Itoa(num))
		log.Error(err)
		return
	}

	errNo := C.init(C.CString(filepath))
	if errNo != 0 {
		err = errors.Wrap(ErrReadFile, strconv.Itoa(int(errNo)))
		log.Error(err)
		return
	}

	// print none if num is out of bounds
	C.print_specific_frame_hex_data(C.int(num))

	return
}

// InitCapFile init capture file only once TODO modify previous function
func InitCapFile(inputFilepath string) (err error) {
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

// ProtoTreeToJsonAllFrame transfer proto tree to json format
func ProtoTreeToJsonAllFrame(inputFilepath string) (resBytes []byte, err error) {
	// init cap file only once
	err = InitCapFile(inputFilepath)
	if err != nil {
		log.Error(err)
		return
	}

	counter := 1
	allFrameRes := make(map[string]string)
	// TODO when get the size of capture file, use parallel logic
	for {
		// The core logic is implemented by c
		src := C.json_tree(C.int(counter))

		frameData := CChar2GoStr(src)
		log.Error(counter, frameData)

		allFrameRes[strconv.Itoa(counter)] = frameData
		counter++

		if frameData == "" {
			log.Error("result is blank")
			break
		}

		if counter == 4 {
			break
		}

	}

	resBytes, err = json.Marshal(allFrameRes)
	if err != nil {
		log.Error(err)
	}

	return
}

// ProtoTreeToJsonSpecificFrame transfer specific frame proto tree to json format
func ProtoTreeToJsonSpecificFrame(inputFilepath string, num int) (resBytes []byte, err error) {
	// init cap file only once
	err = InitCapFile(inputFilepath)
	if err != nil {
		log.Error(err)
		return
	}

	counter := 0
	allFrameRes := make(map[string]string)
	// TODO when get the size of capture file, use parallel logic
	for {
		counter++
		if counter < num && num != counter {
			continue
		}

		// The core logic is implemented by c
		src := C.json_tree(C.int(counter))
		frameData := CChar2GoStr(src)
		if frameData == "" {
			log.Error("result is blank")
			break
		}

		allFrameRes[strconv.Itoa(counter)] = frameData

		break
	}

	resBytes, err = json.Marshal(allFrameRes)
	if err != nil {
		log.Error(err)
		return
	}

	return
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

// GetSpecificFrameHexData get specific frame hex data
func GetSpecificFrameHexData(inputFilepath string, num int) (resBytes []byte, err error) {
	// init cap file only once
	err = InitCapFile(inputFilepath)
	if err != nil {
		log.Error(err)
		return
	}

	src := C.print_specific_frame_hex_data(C.int(num))
	hexData := CChar2GoStr(src)
	if hexData == "" {
		log.Error("result is blank")
		return
	}

	resBytes, err = json.Marshal(hexData)
	if err != nil {
		log.Error(err)
		return
	}

	return
}
