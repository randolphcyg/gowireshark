package gowireshark

/*
#include "bridge.h"
#include "offline.h"

static int call_write_pcap_slice_native(char *input_path, char *output_path, int *indices, int idx_count, char *output_format) {
    return write_pcap_slice_native(input_path, output_path, indices, idx_count, output_format);
}
*/
import "C"
import (
	"io"
	"os"
	"unsafe"

	"github.com/pkg/errors"
)

func writePcapSliceNative(path string, w io.Writer, indices []int, outputFormat string) (int, error) {
	tmp, err := os.CreateTemp("", "gowireshark-pcap-slice-")
	if err != nil {
		return 0, errors.Wrap(err, "create temp file")
	}
	tmpPath := tmp.Name()
	tmp.Close()
	defer os.Remove(tmpPath)

	cInputPath := C.CString(path)
	cOutputPath := C.CString(tmpPath)
	defer C.free(unsafe.Pointer(cInputPath))
	defer C.free(unsafe.Pointer(cOutputPath))

	var cOutputFormat *C.char
	if outputFormat != "" {
		cOutputFormat = C.CString(outputFormat)
		defer C.free(unsafe.Pointer(cOutputFormat))
	}

	cIndicesSlice := make([]C.int, len(indices))
	for i, v := range indices {
		cIndicesSlice[i] = C.int(v)
	}
	cIndices := (*C.int)(unsafe.Pointer(&cIndicesSlice[0]))
	cCount := C.int(len(indices))

	epanMu.Lock()
	defer epanMu.Unlock()
	ret := C.call_write_pcap_slice_native(cInputPath, cOutputPath, cIndices, cCount, cOutputFormat)

	if ret < 0 {
		if ret == -2 {
			return 0, ErrEmptySelection
		}
		return 0, &WiretapError{
			Operation: "native pcap slice",
			Code:      int(ret),
			Message:   "wiretap writer returned an error",
			Err:       ErrReadCaptureFile,
		}
	}

	out, err := os.Open(tmpPath)
	if err != nil {
		return 0, errors.Wrap(err, "open temp output")
	}
	defer out.Close()
	n, err := io.Copy(w, out)
	if err != nil {
		return int(n), errors.Wrap(err, "copy pcap output")
	}
	return len(indices), nil
}
