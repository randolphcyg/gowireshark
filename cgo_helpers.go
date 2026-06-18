package gowireshark

/*
#include "bridge.h"
#include "offline.h"

// Forward declaration of the Go exported callback
extern int onFrameCallback(char *json, int len, int err);

// Wrappers to pass the Go function pointer to C
static void call_get_frames_by_range(int start, int limit, int printCJson, char *filter) {
    get_frames_by_range(start, limit, printCJson, filter, onFrameCallback);
}

static void call_get_all_frames_cb(int printCJson, char *filter) {
    get_all_frames_cb(printCJson, filter, onFrameCallback);
}

static void call_get_frames_by_idxs_cb(int *idxs, int count, int printCJson) {
    get_frames_by_idxs_cb(idxs, count, printCJson, onFrameCallback);
}

static void call_get_stream_payloads_cb(char *filter, char *proto) {
    get_stream_payloads_cb(filter, proto, onFrameCallback);
}

static int call_get_tap_conversations_cb(char *filter, char *conv_type) {
    return get_tap_conversations_cb(filter, conv_type, onFrameCallback);
}

static int call_get_tap_endpoints_cb(char *filter, char *endpoint_type) {
    return get_tap_endpoints_cb(filter, endpoint_type, onFrameCallback);
}

static int call_get_export_objects_cb(char *filter, char *protocol) {
    return get_export_objects_cb(filter, protocol, onFrameCallback);
}

static int call_write_export_object_cb(char *filter, char *protocol, int packet_num) {
    return write_export_object_cb(filter, protocol, packet_num, onFrameCallback);
}

static int call_get_service_response_times_cb(char *filter, char *protocol) {
    return get_service_response_times_cb(filter, protocol, onFrameCallback);
}

static int call_get_fields_rows_cb(char **fields, int field_count, char *filter) {
    return get_fields_rows_cb((const char **)fields, field_count, filter, onFrameCallback);
}

static int call_get_fields_rows_occurrence_cb(char **fields, int field_count, char *filter, int occurrence) {
    return get_fields_rows_occurrence_cb((const char **)fields, field_count, filter, occurrence, onFrameCallback);
}

static int call_write_pcap_slice_native(char *input_path, char *output_path, int *indices, int idx_count, char *output_format) {
    return write_pcap_slice_native(input_path, output_path, indices, idx_count, output_format);
}

static int call_get_frame_numbers_filtered(char *filter_str, int **numbers_out) {
    return get_frame_numbers_filtered(filter_str, numbers_out);
}

static char *call_get_timeline_json(char *filter_str) {
    return get_timeline_json(filter_str);
}

static int call_get_proto_hierarchy_cb(char *filter_str) {
    return get_proto_hierarchy_cb(filter_str, onFrameCallback);
}

static int call_get_io_stats_cb(char *filter_str, double interval) {
    return get_io_stats_cb(filter_str, interval, onFrameCallback);
}
*/
import "C"
import (
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"unsafe"

	"github.com/bytedance/sonic"
	"github.com/pkg/errors"
)

// globalFrameChan bridges C callbacks to Go consumers for bulk parsing paths.
// globalFrameSink is used when the callback itself must control flow, such as
// WalkFrames early-stop and writer failures. Both are protected by epanMu.
var (
	globalFrameChan chan []byte
	globalFrameSink func([]byte) bool
)

func cleanupGlobalState() {
	globalFrameSink = nil
	globalFrameChan = nil
}

// withSink temporarily replaces the global frame sink with fn, runs the
// provided operation, and restores the original sink. This is used by
// streaming frame walkers to capture frames without channel overhead.
func withSink(fn func([]byte) bool, op func() error) error {
	epanMu.Lock()
	original := globalFrameSink
	globalFrameSink = fn
	epanMu.Unlock()
	defer func() {
		epanMu.Lock()
		globalFrameSink = original
		epanMu.Unlock()
	}()
	return op()
}

// onFrameCallback
// This function is called from C. It copies the JSON string to Go memory and pushes it to the channel.
//
//export onFrameCallback
func onFrameCallback(jsonStr *C.char, length C.int, errCode C.int) C.int {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("Panic in onFrameCallback", "err", r)
			cleanupGlobalState()
		}
	}()

	if errCode != 0 {
		return 0
	}
	if jsonStr == nil || length <= 0 {
		return 0
	}

	goBytes := C.GoBytes(unsafe.Pointer(jsonStr), length)
	if globalFrameSink != nil {
		if !globalFrameSink(goBytes) {
			return 1
		}
		return 0
	}
	if globalFrameChan != nil {
		globalFrameChan <- goBytes
	}
	return 0
}

var (
	// ErrFileNotFound reports that the requested capture file does not exist.
	ErrFileNotFound = errors.New("capture file not found")
	// ErrReadCaptureFile reports that libwireshark failed to open or read a capture file.
	ErrReadCaptureFile = errors.New("failed to read capture file")
	// ErrParseDissectionResult reports malformed JSON emitted by the C bridge.
	ErrParseDissectionResult = errors.New("failed to parse dissection result")
	// ErrFrameNotFound reports that libwireshark returned no payload for the requested frame.
	ErrFrameNotFound = errors.New("frame not found")
)

func getOptimalWorkerNum(taskSize int) int {
	cpuNum := runtime.NumCPU()
	if taskSize > 0 && taskSize < cpuNum {
		return taskSize
	}
	if cpuNum < 1 {
		return 1
	}
	return cpuNum
}

// sortFrames sorts frames by frame number, safely handling nil Frame layers.
func sortFrames(frames []*FrameData) {
	slices.SortFunc(frames, func(a, b *FrameData) int {
		an, bn := 0, 0
		if a.BaseLayers.Frame != nil {
			an = a.BaseLayers.Frame.Number
		}
		if b.BaseLayers.Frame != nil {
			bn = b.BaseLayers.Frame.Number
		}
		return an - bn
	})
}

// epanMu serializes libwireshark access because libwireshark keeps global state.
var epanMu sync.Mutex

// init initializes the Wireshark environment once on startup.
func init() {
	if !C.init_env() {
		panic("failed to initialize wireshark env")
	}
}

func cString(src *C.char) string {
	return C.GoStringN(src, C.int(C.strlen(src)))
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// PluginsSupported reports whether the linked EPAN build supports plugins.
func PluginsSupported() bool {
	return C.epan_plugins_supported() != 0
}

func sessionResetReadPosition() error {
	if errNo := C.session_reset_read_position(); errNo != 0 {
		return errors.Wrap(ErrReadCaptureFile, strconv.Itoa(int(errNo)))
	}
	return nil
}

func sessionCountFrames(filter string) int {
	cFilter := C.CString(filter)
	defer C.free(unsafe.Pointer(cFilter))
	return int(C.count_frames(cFilter))
}

func sessionGetFrameNumbers(filter string) ([]int, error) {
	cFilter := C.CString(filter)
	defer C.free(unsafe.Pointer(cFilter))

	var cNumbers *C.int
	count := C.call_get_frame_numbers_filtered(cFilter, &cNumbers)

	if count < 0 {
		return nil, errors.New("filter compile error")
	}
	if count == 0 {
		return []int{}, nil
	}
	defer C.g_free(C.gpointer(unsafe.Pointer(cNumbers)))

	numbers := make([]int, count)
	for i := range numbers {
		ptr := (*C.int)(unsafe.Pointer(uintptr(unsafe.Pointer(cNumbers)) + uintptr(i)*unsafe.Sizeof(*cNumbers)))
		numbers[i] = int(*ptr)
	}
	return numbers, nil
}

func sessionGetTimelineJSON(filter string) (string, error) {
	cFilter := C.CString(filter)
	defer C.free(unsafe.Pointer(cFilter))

	cjson := C.call_get_timeline_json(cFilter)
	if cjson == nil {
		return "", errors.New("timeline extraction failed")
	}
	defer C.g_free(C.gpointer(unsafe.Pointer(cjson)))
	return C.GoString(cjson), nil
}

func sessionBuildIndex() (int, error) {
	count := int(C.build_frame_index())
	if count < 0 {
		return 0, errors.Wrap(ErrReadCaptureFile, "failed to build frame index")
	}
	return count, nil
}

func sessionFreeIndex() {
	C.free_frame_index()
}

func sessionDoClose() {
	C.close_capture_file()
}

func sessionWalkAllFramesJSON(filter string) error {
	cFilter := C.CString(filter)
	defer C.free(unsafe.Pointer(cFilter))
	C.call_get_all_frames_cb(C.int(0), cFilter)
	return nil
}

func sessionWalkFieldsFast(filter string, fields []string) error {
	if len(fields) == 0 {
		return nil
	}
	cFields := make([]*C.char, len(fields))
	for i, f := range fields {
		cFields[i] = C.CString(f)
		defer C.free(unsafe.Pointer(cFields[i]))
	}
	cFilter := C.CString(filter)
	defer C.free(unsafe.Pointer(cFilter))
	ret := C.call_get_fields_rows_cb(&cFields[0], C.int(len(fields)), cFilter)
	if ret != 0 {
		return errors.Wrapf(ErrInvalidDisplayFilter, "filter compile failed: %q", filter)
	}
	return nil
}

func sessionWalkFieldsOccurrence(filter string, fields []string, occurrence int) error {
	if occurrence == 0 {
		return sessionWalkFieldsFast(filter, fields)
	}
	if len(fields) == 0 {
		return nil
	}
	cFields := make([]*C.char, len(fields))
	for i, f := range fields {
		cFields[i] = C.CString(f)
		defer C.free(unsafe.Pointer(cFields[i]))
	}
	cFilter := C.CString(filter)
	defer C.free(unsafe.Pointer(cFilter))
	ret := C.call_get_fields_rows_occurrence_cb(&cFields[0], C.int(len(fields)), cFilter, C.int(occurrence))
	if ret != 0 {
		return errors.Wrapf(ErrInvalidDisplayFilter, "filter compile failed: %q", filter)
	}
	return nil
}

func getExpertInfosBatch(filter string) ([]ExpertInfo, error) {
	cFilter := C.CString(filter)
	defer C.free(unsafe.Pointer(cFilter))

	result := C.get_expert_infos_json(cFilter)
	if result == nil {
		return []ExpertInfo{}, nil
	}
	defer C.free_c_string(result)

	var items []ExpertInfo
	if err := sonic.Unmarshal([]byte(C.GoString(result)), &items); err != nil {
		return nil, err
	}
	return items, nil
}

type fastFollowPayload struct {
	Summary      bool   `json:"_summary"`
	MatchedCount int    `json:"matched_count"`
	Src          string `json:"src"`
	Dst          string `json:"dst"`
	SrcPort      int    `json:"srcport"`
	DstPort      int    `json:"dstport"`
	Payload      string `json:"payload"`
}

type fastFollowPayloadBatch struct {
	MatchedCount int                 `json:"matched_count"`
	Payloads     []fastFollowPayload `json:"payloads"`
}

func getStreamPayloadsBatch(filter, proto string) (*FollowResult, error) {
	cFilter := C.CString(filter)
	cProto := C.CString(proto)
	defer C.free(unsafe.Pointer(cFilter))
	defer C.free(unsafe.Pointer(cProto))

	result := C.get_stream_payloads_json(cFilter, cProto)
	if result == nil {
		return &FollowResult{}, nil
	}
	defer C.free_c_string(result)

	var batch fastFollowPayloadBatch
	if err := sonic.Unmarshal([]byte(C.GoString(result)), &batch); err != nil {
		return nil, err
	}

	out := &FollowResult{
		ClientNode: "Client",
		ServerNode: "Server",
	}
	clientPort := -1
	currentDir := ""
	var currentBuilder strings.Builder

	out.PacketCount = batch.MatchedCount

	for _, fastFrame := range batch.Payloads {
		if fastFrame.Payload == "" {
			continue
		}

		if clientPort == -1 && fastFrame.SrcPort != 0 {
			clientPort = fastFrame.SrcPort
			out.ClientNode = fmt.Sprintf("%s:%d", fastFrame.Src, fastFrame.SrcPort)
			out.ServerNode = fmt.Sprintf("%s:%d", fastFrame.Dst, fastFrame.DstPort)
		}

		dir := "server"
		if fastFrame.SrcPort == clientPort {
			dir = "client"
		}

		bytesLen := len(fastFrame.Payload) / 2
		if dir == "client" {
			out.ClientBytes += bytesLen
		} else {
			out.ServerBytes += bytesLen
		}

		if currentDir == "" {
			currentDir = dir
			currentBuilder.WriteString(fastFrame.Payload)
		} else if currentDir == dir {
			currentBuilder.WriteString(fastFrame.Payload)
		} else {
			out.Payloads = append(out.Payloads, newFollowPayload(currentDir, currentBuilder.String()))
			currentDir = dir
			currentBuilder.Reset()
			currentBuilder.WriteString(fastFrame.Payload)
		}
	}

	if currentDir != "" {
		out.Payloads = append(out.Payloads, newFollowPayload(currentDir, currentBuilder.String()))
	}
	if len(out.Payloads) == 0 {
		out.Payloads = append(out.Payloads, FollowPayload{Dir: "client", HexData: ""})
	}

	return out, nil
}
