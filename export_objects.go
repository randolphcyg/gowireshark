package gowireshark

/*
#include "bridge.h"
#include "offline.h"

// Forward declaration of the Go exported callback
extern int onFrameCallback(char *json, int len, int err);

static int call_get_export_objects_cb(char *filter, char *protocol) {
    return get_export_objects_cb(filter, protocol, onFrameCallback);
}

static int call_write_export_object_cb(char *filter, char *protocol, int packet_num) {
    return write_export_object_cb(filter, protocol, packet_num, onFrameCallback);
}
*/
import "C"
import (
	"context"
	"encoding/hex"
	"io"
	"strings"
	"unsafe"

	"github.com/bytedance/sonic"
	"github.com/pkg/errors"
)

type fastExportObject struct {
	PacketNum   int    `json:"packetNum"`
	Hostname    string `json:"hostname,omitempty"`
	ContentType string `json:"contentType,omitempty"`
	Filename    string `json:"filename,omitempty"`
	Length      int64  `json:"length"`
	SHA256      string `json:"sha256,omitempty"`
}

type exportObjectWriteItem struct {
	PacketNum   int    `json:"packetNum"`
	Hostname    string `json:"hostname,omitempty"`
	ContentType string `json:"contentType,omitempty"`
	Filename    string `json:"filename,omitempty"`
	Length      int64  `json:"length"`
	PayloadHex  string `json:"payloadHex,omitempty"`
}

// ExportObject is STABLE.
// ExportObject describes one file-like object found in a capture via Wireshark's export object tap.
type ExportObject struct {
	Protocol    string `json:"protocol"`
	PacketNum   int    `json:"packetNum"`
	Hostname    string `json:"hostname,omitempty"`
	ContentType string `json:"contentType,omitempty"`
	Filename    string `json:"filename,omitempty"`
	Length      int64  `json:"length"`
	SHA256      string `json:"sha256,omitempty"`
}

var supportedExportProtocols = map[string]bool{
	"http":     true,
	"smb":      true,
	"tftp":     true,
	"ftp-data": true,
	"imf":      true,
	"dicom":    true,
}

func fastEOToExportObject(fast fastExportObject, protocol string) ExportObject {
	return ExportObject{
		Protocol:    protocol,
		PacketNum:   fast.PacketNum,
		Hostname:    fast.Hostname,
		ContentType: fast.ContentType,
		Filename:    fast.Filename,
		Length:      fast.Length,
		SHA256:      fast.SHA256,
	}
}

// SupportsExportObjects reports whether a protocol has an export-object tap
// registered in the current libwireshark runtime.
func SupportsExportObjects(protocol string) bool {
	return supportedExportProtocols[protocol]
}

// ExportObjectProtocols returns the list of supported export-object protocols.
func ExportObjectProtocols() []string {
	return []string{"http", "smb", "tftp", "ftp-data", "imf", "dicom"}
}

// ExportObjects returns file objects found via Wireshark's export object tap.
func ExportObjects(path string, protocol string, opts ...Option) ([]ExportObject, error) {
	return ExportObjectsContext(context.Background(), path, protocol, opts...)
}

// ExportObjectsContext returns file objects found via Wireshark's export object
// tap using the provided context for session acquisition.
func ExportObjectsContext(ctx context.Context, path string, protocol string, opts ...Option) ([]ExportObject, error) {
	s, err := OpenSessionContext(ctx, path, opts...)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return s.ExportObjects(protocol, Query{Filter: extractFilter(opts)})
}

// WriteExportObject writes the payload of one export object to w.
func WriteExportObject(path string, protocol string, packetNum int, w io.Writer, opts ...Option) error {
	return WriteExportObjectContext(context.Background(), path, protocol, packetNum, w, opts...)
}

// WriteExportObjectContext writes the payload of one export object using the
// provided context for session acquisition.
func WriteExportObjectContext(ctx context.Context, path string, protocol string, packetNum int, w io.Writer, opts ...Option) error {
	s, err := OpenSessionContext(ctx, path, opts...)
	if err != nil {
		return err
	}
	defer s.Close()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return s.WriteExportObject(protocol, packetNum, w, Query{Filter: extractFilter(opts)})
}

func sanitizeFilename(name string) string {
	name = strings.ReplaceAll(name, "/", "_")
	name = strings.ReplaceAll(name, "..", "_")
	name = strings.ReplaceAll(name, "\x00", "")
	if name == "" || name == "." {
		return "unknown.bin"
	}
	return name
}

// WriteExportObjects writes all export objects for a protocol to dir.
func WriteExportObjects(path string, protocol string, dir string, opts ...Option) ([]ExportObject, error) {
	return WriteExportObjectsContext(context.Background(), path, protocol, dir, opts...)
}

// WriteExportObjectsContext writes all export objects for a protocol using the
// provided context for session acquisition.
func WriteExportObjectsContext(ctx context.Context, path string, protocol string, dir string, opts ...Option) ([]ExportObject, error) {
	s, err := OpenSessionContext(ctx, path, opts...)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return s.WriteExportObjects(protocol, dir, Query{Filter: extractFilter(opts)})
}

func exportObjectsFromActive(protocol string, filter string) ([]ExportObject, error) {
	if !supportedExportProtocols[protocol] {
		return nil, errors.Wrapf(ErrUnsupportedProtocol,
			"export protocol %q (supported: http, smb, tftp, ftp-data, imf, dicom)", protocol)
	}
	if filter != "" {
		if err := ValidateFilter(filter); err != nil {
			return nil, err
		}
	}

	out := make([]ExportObject, 0)
	var parseErr error

	globalFrameSink = func(jsonBytes []byte) bool {
		var fast fastExportObject
		if err := sonic.Unmarshal(jsonBytes, &fast); err != nil {
			parseErr = err
			return false
		}
		out = append(out, fastEOToExportObject(fast, protocol))
		return true
	}
	defer cleanupGlobalState()

	cFilter := C.CString(filter)
	cProto := C.CString(protocol)
	defer C.free(unsafe.Pointer(cFilter))
	defer C.free(unsafe.Pointer(cProto))

	if ret := C.call_get_export_objects_cb(cFilter, cProto); ret != 0 {
		return out, errors.Wrapf(ErrReadCaptureFile, "export objects tap failed: %d", int(ret))
	}
	if parseErr != nil {
		return out, parseErr
	}
	return out, nil
}

func writeExportObjectFromActive(protocol string, packetNum int, filter string, w io.Writer) error {
	if !supportedExportProtocols[protocol] {
		return errors.Wrapf(ErrUnsupportedProtocol,
			"export protocol %q (supported: http, smb, tftp, ftp-data, imf, dicom)", protocol)
	}
	if filter != "" {
		if err := ValidateFilter(filter); err != nil {
			return err
		}
	}

	var foundData []byte
	var found bool
	var parseErr error

	globalFrameSink = func(jsonBytes []byte) bool {
		var item exportObjectWriteItem
		if err := sonic.Unmarshal(jsonBytes, &item); err != nil {
			parseErr = err
			return false
		}
		if item.PacketNum == packetNum {
			found = true
			if item.PayloadHex != "" {
				var err error
				foundData, err = hex.DecodeString(item.PayloadHex)
				if err != nil {
					parseErr = err
					return false
				}
			}
		}
		return true
	}
	defer cleanupGlobalState()

	cFilter := C.CString(filter)
	cProto := C.CString(protocol)
	defer C.free(unsafe.Pointer(cFilter))
	defer C.free(unsafe.Pointer(cProto))

	if ret := C.call_write_export_object_cb(cFilter, cProto, C.int(packetNum)); ret != 0 {
		return errors.Wrapf(ErrReadCaptureFile, "export objects tap failed: %d", int(ret))
	}
	if parseErr != nil {
		return parseErr
	}
	if !found {
		return ErrFrameNotFound
	}
	_, err := w.Write(foundData)
	return err
}
