package gowireshark

/*
#cgo pkg-config: glib-2.0
#cgo LDFLAGS: -L${SRCDIR}/libs -lwiretap -lwsutil -lwireshark
#cgo LDFLAGS: -Wl,-rpath,${SRCDIR}/libs
#cgo CFLAGS: -I${SRCDIR}/include/wireshark
#cgo CFLAGS: -std=c99

#include <cfile.h>
#include <epan/column.h>
#include <epan/epan.h>
#include <epan/epan_dissect.h>
#include <epan/frame_data.h>
#include <epan/frame_data_sequence.h>
#include <epan/print.h>
#include <epan/print_stream.h>
#include <epan/tvbuff.h>
#include <stdio.h>
#include <wiretap/wtap-int.h>
#include <wiretap/wtap.h>
#include <wsutil/nstime.h>
#include <wsutil/privileges.h>
// init modules & init capture_file
int init(char *filename);
// Dissect and print all frames
void print_all_frame();
// Dissect and print the first frame
void print_first_frame();
// Dissect and print the first several frames
void print_first_several_frame(int count);
*/
import "C"
import (
	"strconv"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/randolphcyg/gowireshark/common/middleware/logger"
	"github.com/randolphcyg/gowireshark/common/tool"
)

var (
	ErrFileNotFound = errors.New("cannot open file, no such file")
	ErrReadFile     = errors.New("occur error when read file ")
	ErrIllegalPara  = errors.New("illegal parameter")
)

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
		return err
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
		return err
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
		return err
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
