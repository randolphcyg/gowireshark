package gowireshark

/*
#cgo pkg-config: glib-2.0
#cgo LDFLAGS: -L${SRCDIR}/libs -lwiretap -lwsutil -lwireshark
#cgo LDFLAGS: -Wl,-rpath,${SRCDIR}/libs
#cgo CFLAGS: -I${SRCDIR}/include/wireshark
#cgo CFLAGS: -std=c99

#include <stdio.h>
#include <cfile.h>
#include <epan/column.h>
#include <epan/epan.h>
#include <epan/tvbuff.h>
#include <epan/frame_data_sequence.h>
#include <epan/frame_data.h>
#include <epan/epan_dissect.h>
#include <epan/print.h>
#include <epan/print_stream.h>
#include <wiretap/wtap.h>
#include <wiretap/wtap-int.h>
#include <wsutil/nstime.h>
#include <wsutil/privileges.h>
// init modules & init capture_file
int init(char *filename);
// print the whole frame
void print_all_packet_text();
// print the first frame
void print_first_packet_text();
*/
import "C"
import (
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/randolphcyg/gowireshark/common/middleware/logger"
	"github.com/randolphcyg/gowireshark/common/tool"
)

var (
	ErrFileNotFound = errors.New("cannot open file, no such file")
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

// DissectFirstPkt dissect all package in a pcap file but only print the first package
func DissectFirstPkt(filepath string) (err error) {
	if !tool.IsFileExist(filepath) {
		err = errors.Wrap(ErrFileNotFound, filepath)
		log.Error(err)
		return err
	}

	C.init(C.CString(filepath))

	C.print_first_packet_text()

	return
}

// DissectAllPkt dissect and print all package in a pcap file
func DissectAllPkt(filepath string) (err error) {
	if !tool.IsFileExist(filepath) {
		err = errors.Wrap(ErrFileNotFound, filepath)
		log.Error(err)
		return err
	}

	C.init(C.CString(filepath))

	C.print_all_packet_text()

	return
}
