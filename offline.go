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
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
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

// initCapFile initializes the capture file structure in C.
func initCapFile(path string, opts ...Option) (conf *config, err error) {
	if _, statErr := os.Stat(path); statErr != nil {
		err = errors.Wrap(ErrFileNotFound, path)
		return
	}

	conf = newConfig(opts...)
	if err = validateDecodeAsRules(conf.DecodeAs); err != nil {
		return nil, err
	}

	cPath := C.CString(path)
	cOptions := C.CString(marshalConfig(conf))
	defer C.free(unsafe.Pointer(cPath))
	defer C.free(unsafe.Pointer(cOptions))

	errNo := C.init_cf(cPath, cOptions)
	if errNo != 0 {
		if errNo == -2 {
			err = ErrUnsupportedProtocol
			return
		}
		if errNo == -3 {
			err = ErrInvalidProfile
			return
		}
		if errNo == -4 {
			err = ErrInvalidPreference
			return
		}
		err = errors.Wrap(ErrReadCaptureFile, strconv.Itoa(int(errNo)))
		return
	}

	return
}

// HexData represents the hex dump format.
type HexData struct {
	Offset []string `json:"offset"`
	Hex    []string `json:"hex"`
	Ascii  []string `json:"ascii"`
}

// parseHexData unmarshal JSON hex data.
func parseHexData(src string) (hexData *HexData, err error) {
	err = sonic.Unmarshal([]byte(src), &hexData)
	return
}

// HexDataByFrameNumber retrieves the hex dump for a 1-based Wireshark frame number.
func HexDataByFrameNumber(path string, frameNum int, opts ...Option) (*HexData, error) {
	return HexDataByFrameNumberContext(context.Background(), path, frameNum, opts...)
}

// HexDataByFrameNumberContext retrieves the hex dump for a 1-based Wireshark
// frame number using the provided context for session acquisition.
func HexDataByFrameNumberContext(ctx context.Context, path string, frameNum int, opts ...Option) (*HexData, error) {
	s, err := OpenSessionContext(ctx, path, opts...)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return s.HexData(frameNum)
}

// ParseFrameData parses the JSON representation of a dissected frame.
func ParseFrameData(src []byte, opts ...Option) (frame *FrameData, err error) {
	if len(src) == 0 {
		return nil, errors.New("empty input data")
	}

	err = sonic.Unmarshal(src, &frame)
	if err != nil {
		return nil, ErrParseDissectionResult
	}

	conf := newConfig(opts...)
	if conf.ParseMode == ParseRawLayers {
		return frame, nil
	}

	var layerErrors []error

	if conf.ParseMode == ParseBaseLayers || conf.ParseMode == ParseSelectedLayers {

		// Parse base layers — each method returns concrete type, nil on not-found
		if shouldParseLayer(conf, "frame") {
			if v, e := frame.Layers.Frame(); e == nil {
				frame.BaseLayers.Frame = v
			} else if !errors.Is(e, ErrLayerNotFound) {
				layerErrors = append(layerErrors, e)
			}
		}

		if shouldParseLayer(conf, "ws_col") {
			if v, e := frame.Layers.WSCol(); e == nil {
				frame.BaseLayers.WSCol = v
			} else if !errors.Is(e, ErrLayerNotFound) {
				layerErrors = append(layerErrors, e)
			}
		}

		if shouldParseLayer(conf, "eth") {
			if v, e := frame.Layers.ETH(); e == nil {
				frame.BaseLayers.ETH = v
			} else if !errors.Is(e, ErrLayerNotFound) {
				layerErrors = append(layerErrors, e)
			}
		}

		if shouldParseLayer(conf, "ip") {
			if v, e := frame.Layers.IP(); e == nil {
				frame.BaseLayers.IP = v
			} else if !errors.Is(e, ErrLayerNotFound) {
				layerErrors = append(layerErrors, e)
			}
		}

		if shouldParseLayer(conf, "udp") {
			if v, e := frame.Layers.UDP(); e == nil {
				frame.BaseLayers.UDP = v
			} else if !errors.Is(e, ErrLayerNotFound) {
				layerErrors = append(layerErrors, e)
			}
		}

		if shouldParseLayer(conf, "tcp") {
			if v, e := frame.Layers.TCP(); e == nil {
				frame.BaseLayers.TCP = v
			} else if !errors.Is(e, ErrLayerNotFound) {
				layerErrors = append(layerErrors, e)
			}
		}

		if shouldParseLayer(conf, "http") {
			if v, e := frame.Layers.HTTP(); e == nil {
				frame.BaseLayers.HTTP = v
			} else if !errors.Is(e, ErrLayerNotFound) {
				layerErrors = append(layerErrors, e)
			}
		}

		if shouldParseLayer(conf, "dns") {
			if v, e := frame.Layers.DNS(); e == nil {
				frame.BaseLayers.DNS = v
			} else if !errors.Is(e, ErrLayerNotFound) {
				layerErrors = append(layerErrors, e)
			}
		}

		conf = newConfig(opts...)
		if conf.Registry != nil && conf.Registry.Len() > 0 {
			if customResults := conf.Registry.ParseAll(frame.Layers); len(customResults) > 0 {
				frame.CustomLayers = customResults
			}
		}

	} // end ParseBaseLayers block

	if len(layerErrors) > 0 {
		frameNum := 0
		if frame.BaseLayers.Frame != nil {
			frameNum = frame.BaseLayers.Frame.Number
		}
		return frame, errors.Errorf("frame:%d errors:%v", frameNum, layerErrors)
	}

	return frame, nil
}

func shouldParseLayer(conf *config, layer string) bool {
	if conf.ParseMode != ParseSelectedLayers {
		return true
	}
	for _, l := range conf.SelectedLayers {
		if strings.EqualFold(l, layer) {
			return true
		}
	}
	return false
}

// FrameByNumberContext gets a single frame by its 1-based Wireshark frame
// number using the provided context for session acquisition.
func FrameByNumberContext(ctx context.Context, path string, frameNum int, opts ...Option) (*FrameData, error) {
	if frameNum < 1 {
		return nil, errors.Wrap(ErrInvalidFrameNumber, "frame number must be >= 1")
	}

	s, err := OpenSessionContext(ctx, path, opts...)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return s.Frame(frameNum)
}

func frameByIndexFromActiveConf(conf *config, frameIdx int, parseOpts ...Option) (*FrameData, error) {
	if frameIdx < 1 {
		return nil, errors.Wrap(ErrInvalidFrameNumber, "frameIdx must be >= 1")
	}
	printCJson := 0
	if conf.PrintCJSON {
		printCJson = 1
	}

	var srcFrame *C.char
	srcFrame = C.proto_tree_in_json_seek(C.int(frameIdx), C.int(printCJson))

	if srcFrame == nil || C.strlen(srcFrame) == 0 {
		if srcFrame != nil {
			C.free_c_string(srcFrame)
		}
		return nil, ErrFrameNotFound
	}
	defer C.free_c_string(srcFrame)
	return ParseFrameData([]byte(cString(srcFrame)), parseOpts...)
}

func hexDataByIndexFromActive(frameIdx int) (*HexData, error) {
	if frameIdx < 1 {
		return nil, errors.Wrap(ErrInvalidFrameNumber, "frameIdx must be >= 1")
	}
	srcHex := C.get_specific_frame_hex_data(C.int(frameIdx))
	if srcHex == nil {
		return nil, ErrFrameNotFound
	}
	defer C.free(unsafe.Pointer(srcHex))
	if C.strlen(srcHex) == 0 {
		return nil, ErrFrameNotFound
	}
	return parseHexData(cString(srcHex))
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

// FramesByNumbers fetches specific 1-based Wireshark frame numbers efficiently
// using a single pass.
func FramesByNumbers(path string, frameNums []int, opts ...Option) ([]*FrameData, error) {
	return FramesByNumbersContext(context.Background(), path, frameNums, opts...)
}

// FramesByNumbersContext fetches specific 1-based Wireshark frame numbers
// using the provided context for session acquisition.
func FramesByNumbersContext(ctx context.Context, path string, frameNums []int, opts ...Option) ([]*FrameData, error) {
	if len(frameNums) == 0 {
		return []*FrameData{}, nil
	}

	s, err := OpenSessionContext(ctx, path, opts...)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return s.Frames(frameNums)
}

func framesByIndicesFromConf(conf *config, frameIdxs []int, parseOpts ...Option) (frames []*FrameData, err error) {
	if len(frameIdxs) == 0 {
		return []*FrameData{}, nil
	}

	printCJson := 0
	if conf.PrintCJSON {
		printCJson = 1
	}

	// 1. Pre-process indices (Sort & Compact)
	frameIdxs = removeNegativeAndZero(frameIdxs)
	slices.Sort(frameIdxs)
	frameIdxs = slices.Compact(frameIdxs)

	if len(frameIdxs) == 0 {
		return nil, ErrEmptySelection
	}

	// 2. Setup channel
	frameChan := make(chan []byte, len(frameIdxs))
	globalFrameChan = frameChan
	defer cleanupGlobalState()

	// 3. Start parsing consumer
	var parseWg sync.WaitGroup
	var parseErr error
	var errMutex sync.Mutex
	resultChan := make(chan *FrameData, len(frameIdxs))

	workerNum := getOptimalWorkerNum(len(frameIdxs))

	parseWg.Add(workerNum)
	for i := 0; i < workerNum; i++ {
		go func() {
			defer parseWg.Done()
			for jsonStr := range frameChan {
				frame, e := ParseFrameData(jsonStr, parseOpts...)
				if e != nil {
					if !conf.IgnoreErrors {
						errMutex.Lock()
						parseErr = e
						errMutex.Unlock()
					} else {
						slog.Warn("FramesByNumbers Parse Error", "err", e)
					}
					continue
				}
				resultChan <- frame
			}
		}()
	}

	// 4. Convert Go slice to C array (Safe handling for int sizes)
	cIdxsSlice := make([]C.int, len(frameIdxs))
	for i, v := range frameIdxs {
		cIdxsSlice[i] = C.int(v)
	}

	// 5. Call C function
	cIdxs := (*C.int)(unsafe.Pointer(&cIdxsSlice[0]))
	cCount := C.int(len(cIdxsSlice))
	C.call_get_frames_by_idxs_cb(cIdxs, cCount, C.int(printCJson))

	// 6. Cleanup
	close(frameChan)

	parseWg.Wait()
	close(resultChan)

	for f := range resultChan {
		frames = append(frames, f)
	}

	sortFrames(frames)

	if parseErr != nil {
		return frames, parseErr
	}
	if len(frames) == 0 {
		return frames, ErrEmptySelection
	}

	return frames, nil
}

// ValidateFilter checks if the given display filter syntax is valid.
func ValidateFilter(filter string) error {
	if filter == "" {
		return nil
	}
	cFilter := C.CString(filter)
	defer C.free(unsafe.Pointer(cFilter))
	cErrMsg := C.validate_filter(cFilter)
	if cErrMsg != nil {
		defer C.free_c_string(cErrMsg)
		return &DisplayFilterError{Filter: filter, Message: cString(cErrMsg)}
	}
	return nil
}

// FilterValidationResult contains detailed display filter validation info.
type FilterValidationResult struct {
	Valid  bool     `json:"valid"`
	Error  string   `json:"error,omitempty"`
	Fields []string `json:"fields,omitempty"`
}

func extractFilterFields(filter string) []string {
	seen := map[string]bool{}
	var fields []string

	start := -1
	for i := 0; i < len(filter); i++ {
		c := filter[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '_' || c == '.' {
			if start < 0 {
				start = i
			}
		} else {
			if start >= 0 {
				tok := filter[start:i]
				start = -1
				if isValidFilterFieldToken(tok) && !seen[tok] {
					seen[tok] = true
					fields = append(fields, tok)
				}
			}
		}
	}
	if start >= 0 {
		tok := filter[start:]
		if isValidFilterFieldToken(tok) && !seen[tok] {
			fields = append(fields, tok)
		}
	}
	return fields
}

func isValidFilterFieldToken(tok string) bool {
	if len(tok) == 0 || tok[0] == '.' || tok[len(tok)-1] == '.' {
		return false
	}
	if !strings.ContainsRune(tok, '.') {
		return false
	}
	if looksLikeIPv4(tok) {
		return false
	}
	if ValidateField(tok) != nil {
		return false
	}
	return true
}

func looksLikeIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if len(p) == 0 || len(p) > 3 {
			return false
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 {
			return false
		}
	}
	return true
}

// ValidateDisplayFilterDetailed validates a display filter and returns structured feedback.
func ValidateDisplayFilterDetailed(filter string) (*FilterValidationResult, error) {
	if filter == "" {
		return &FilterValidationResult{Valid: true}, nil
	}

	fields := extractFilterFields(filter)

	cFilter := C.CString(filter)
	defer C.free(unsafe.Pointer(cFilter))

	cErrMsg := C.validate_filter(cFilter)
	if cErrMsg != nil {
		defer C.free_c_string(cErrMsg)
		return &FilterValidationResult{
			Valid:  false,
			Error:  cString(cErrMsg),
			Fields: fields,
		}, nil
	}
	return &FilterValidationResult{Valid: true, Fields: fields}, nil
}

// FrameCount returns the number of frames selected by the supplied options.
// Without a filter this is O(1).
func FrameCount(path string, opts ...Option) (int, error) {
	return FrameCountContext(context.Background(), path, opts...)
}

// FrameCountContext returns the number of frames selected by the supplied
// options using the provided context for session acquisition.
func FrameCountContext(ctx context.Context, path string, opts ...Option) (int, error) {
	s, err := OpenSessionContext(ctx, path, opts...)
	if err != nil {
		return 0, err
	}
	defer s.Close()
	if ctx.Err() != nil {
		return 0, ctx.Err()
	}
	return s.FrameCount(Query{Filter: extractFilter(opts)})
}

// FrameNumbers returns sorted 1-based frame numbers matching the supplied
// options. Without a filter this is O(1).
func FrameNumbers(path string, opts ...Option) ([]int, error) {
	return FrameNumbersContext(context.Background(), path, opts...)
}

// FrameNumbersContext returns sorted 1-based frame numbers matching the
// supplied options using the provided context for session acquisition.
func FrameNumbersContext(ctx context.Context, path string, opts ...Option) ([]int, error) {
	s, err := OpenSessionContext(ctx, path, opts...)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return s.FrameNumbers(Query{Filter: extractFilter(opts)})
}

func extractFilter(opts []Option) string {
	return newConfig(opts...).DisplayFilter
}

// Frames fetches all frames efficiently.
func Frames(path string, opts ...Option) ([]*FrameData, error) {
	return FramesContext(context.Background(), path, opts...)
}

// FramesContext fetches all frames using the provided context for session
// acquisition. Prefer WalkFramesContext or IterFrames for large captures.
func FramesContext(ctx context.Context, path string, opts ...Option) ([]*FrameData, error) {
	s, err := OpenSessionContext(ctx, path, opts...)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	var frames []*FrameData
	walkErr := s.WalkFrames(Query{Filter: extractFilter(opts)}, func(f *FrameData) error {
		frames = append(frames, f)
		return nil
	})
	if walkErr != nil {
		return frames, walkErr
	}
	return frames, nil
}

// WriteFrames dissects all selected frames and writes one raw JSON object per line to w.
// It avoids Go-side JSON unmarshal/marshal work; C produces JSON, Go copies the bytes,
// then writes NDJSON to the caller-owned writer.
// Returns the number of frames written.
func WriteFrames(path string, w io.Writer, opts ...Option) (int, error) {
	return WriteFramesContext(context.Background(), path, w, opts...)
}

// WriteFramesContext writes selected frames as NDJSON using the provided
// context for session acquisition.
func WriteFramesContext(ctx context.Context, path string, w io.Writer, opts ...Option) (int, error) {
	s, err := OpenSessionContext(ctx, path, opts...)
	if err != nil {
		return 0, err
	}
	defer s.Close()
	if ctx.Err() != nil {
		return 0, ctx.Err()
	}
	return s.WriteFrames(Query{Filter: extractFilter(opts)}, w)
}

func writeFramesFromConf(conf *config, filter string, w io.Writer) (count int, err error) {
	if filter != "" {
		if err := ValidateFilter(filter); err != nil {
			return 0, err
		}
	}

	printCJson := 0
	if conf.PrintCJSON {
		printCJson = 1
	}

	var writeErr error
	globalFrameSink = func(jsonBytes []byte) bool {
		if e := writeFrameJSONLine(w, jsonBytes, conf); e != nil {
			writeErr = e
			return false
		}
		count++
		return true
	}
	defer cleanupGlobalState()

	cFilter := C.CString(filter)
	defer C.free(unsafe.Pointer(cFilter))

	C.call_get_all_frames_cb(C.int(printCJson), cFilter)

	if writeErr != nil {
		return count, writeErr
	}
	return count, nil
}

// FramesPage fetches a specific page of frames using pagination.
//
// This is a convenience wrapper that creates a temporary Session.
func FramesPage(path string, page, size int, opts ...Option) ([]*FrameData, bool, error) {
	return FramesPageContext(context.Background(), path, page, size, opts...)
}

// FramesPageContext fetches a specific page of frames using the provided
// context for session acquisition.
func FramesPageContext(ctx context.Context, path string, page, size int, opts ...Option) ([]*FrameData, bool, error) {
	s, err := OpenSessionContext(ctx, path, opts...)
	if err != nil {
		return nil, false, err
	}
	defer s.Close()
	if ctx.Err() != nil {
		return nil, false, ctx.Err()
	}
	return s.FramesPage(Query{Filter: extractFilter(opts)}, page, size)
}

func framesPageFromConf(conf *config, filter string, page, size int, parseOpts ...Option) (frames []*FrameData, hasMore bool, err error) {
	frames = make([]*FrameData, 0)

	fetchSize := size + 1
	startFrameIdx := (page-1)*size + 1

	if filter != "" {
		if err := ValidateFilter(filter); err != nil {
			return frames, false, err
		}
	}

	printCJson := 0
	if conf.PrintCJSON {
		printCJson = 1
	}

	frameChan := make(chan []byte, fetchSize)
	globalFrameChan = frameChan
	defer cleanupGlobalState()

	var parseWg sync.WaitGroup
	var parseErr error
	var errMutex sync.Mutex
	resultChan := make(chan *FrameData, fetchSize)

	workerNum := getOptimalWorkerNum(fetchSize)

	parseWg.Add(workerNum)
	for i := 0; i < workerNum; i++ {
		go func() {
			defer parseWg.Done()
			for jsonStr := range frameChan {
				f, e := ParseFrameData(jsonStr, parseOpts...)
				if e != nil {
					if !conf.IgnoreErrors {
						errMutex.Lock()
						parseErr = e
						errMutex.Unlock()
					}
					continue
				}
				resultChan <- f
			}
		}()
	}

	cFilter := C.CString(filter)
	defer C.free(unsafe.Pointer(cFilter))

	C.call_get_frames_by_range(C.int(startFrameIdx), C.int(fetchSize), C.int(printCJson), cFilter)

	close(frameChan)

	parseWg.Wait()
	close(resultChan)

	for f := range resultChan {
		frames = append(frames, f)
	}

	if parseErr != nil {
		return frames, hasMore, parseErr
	}

	sortFrames(frames)

	if conf.Debug {
		slog.Info("Paged parsing completed", "fetched_count", len(frames), "page", page)
	}

	if len(frames) > size {
		hasMore = true
		frames = frames[:size]
	} else {
		hasMore = false
	}

	return frames, hasMore, nil
}

// WriteFramesPage is the NDJSON writer counterpart to FramesPage.
// It writes each selected frame's raw JSON directly to w without Go-side
// unmarshal/marshal work.
// Returns (framesWritten, hasMore, error).
func WriteFramesPage(path string, page, size int, w io.Writer, opts ...Option) (int, bool, error) {
	return WriteFramesPageContext(context.Background(), path, page, size, w, opts...)
}

// WriteFramesPageContext is the NDJSON writer counterpart to FramesPageContext.
func WriteFramesPageContext(ctx context.Context, path string, page, size int, w io.Writer, opts ...Option) (int, bool, error) {
	s, err := OpenSessionContext(ctx, path, opts...)
	if err != nil {
		return 0, false, err
	}
	defer s.Close()
	if ctx.Err() != nil {
		return 0, false, ctx.Err()
	}
	return s.WriteFramesPage(Query{Filter: extractFilter(opts)}, page, size, w)
}

func writeFramesPageFromConf(conf *config, filter string, page, size int, w io.Writer) (count int, hasMore bool, err error) {
	if page < 1 {
		page = 1
	}
	if size < 1 {
		size = 20
	}

	fetchSize := size + 1
	startFrameIdx := (page-1)*size + 1

	if filter != "" {
		if err := ValidateFilter(filter); err != nil {
			return 0, false, err
		}
	}

	printCJson := 0
	if conf.PrintCJSON {
		printCJson = 1
	}

	var writeErr error
	collected := 0
	globalFrameSink = func(jsonBytes []byte) bool {
		collected++
		if collected > size {
			// This is the extra frame for hasMore detection — don't write it.
			return true
		}
		if e := writeFrameJSONLine(w, jsonBytes, conf); e != nil {
			writeErr = e
			return false
		}
		count++
		return true
	}
	defer cleanupGlobalState()

	cFilter := C.CString(filter)
	defer C.free(unsafe.Pointer(cFilter))

	C.call_get_frames_by_range(C.int(startFrameIdx), C.int(fetchSize), C.int(printCJson), cFilter)

	hasMore = collected > size

	if writeErr != nil {
		return count, hasMore, writeErr
	}
	return count, hasMore, nil
}

// WalkFrames walks all frames matched by opts, calling walkFn for each parsed FrameData.
// The FrameData passed to walkFn is only valid during the call; do not retain it.
// If walkFn returns an error, walking stops and that error is returned.
// Unlike Frames(), this does not collect all frames in memory.
//
// This is a convenience wrapper that creates a temporary Session.
func WalkFrames(path string, walkFn func(*FrameData) error, opts ...Option) error {
	s, err := OpenSessionContext(context.Background(), path, opts...)
	if err != nil {
		return err
	}
	defer s.Close()
	return s.WalkFrames(Query{Filter: extractFilter(opts)}, walkFn)
}

func WalkFramesContext(ctx context.Context, path string, walkFn func(*FrameData) error, opts ...Option) error {
	s, err := OpenSessionContext(ctx, path, opts...)
	if err != nil {
		return err
	}
	defer s.Close()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return s.WalkFrames(Query{Filter: extractFilter(opts)}, walkFn)
}

func WriteDissectionContext(ctx context.Context, path string, w io.Writer, format OutputFormat, opts ...Option) (int, error) {
	s, err := OpenSessionContext(ctx, path, opts...)
	if err != nil {
		return 0, err
	}
	defer s.Close()
	if ctx.Err() != nil {
		return 0, ctx.Err()
	}
	return s.writeDissection(w, format, Query{Filter: extractFilter(opts)}, opts...)
}

func FieldsRowsContext(ctx context.Context, path string, fields []string, opts ...Option) ([]FieldRow, error) {
	s, err := OpenSessionContext(ctx, path, opts...)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return s.FieldsRows(Query{Filter: extractFilter(opts)}, fields, opts...)
}

func walkFramesFromConf(conf *config, filter string, walkFn func(*FrameData) error, parseOpts ...Option) error {
	if filter != "" {
		if err := ValidateFilter(filter); err != nil {
			return err
		}
	}

	printCJson := 0
	if conf.PrintCJSON {
		printCJson = 1
	}

	var walkErr error
	globalFrameSink = func(jsonBytes []byte) bool {
		frame, e := ParseFrameData(jsonBytes, parseOpts...)
		if e != nil {
			if !conf.IgnoreErrors {
				walkErr = e
				return false
			}
			slog.Warn("WalkFrames Parse Error", "err", e)
			return true
		}
		if e := walkFn(frame); e != nil {
			walkErr = e
			return false
		}
		return true
	}
	defer cleanupGlobalState()

	cFilter := C.CString(filter)
	defer C.free(unsafe.Pointer(cFilter))

	C.call_get_all_frames_cb(C.int(printCJson), cFilter)

	return walkErr
}

// =======================
// Stream Tracking
// =======================

// FollowPayload contains one directional payload segment from a followed stream.
type FollowPayload struct {
	Dir     string `json:"dir"`
	HexData string `json:"hexData"`
	Bytes   []byte `json:"-"`
}

// FollowResult contains payloads and summary metadata for a followed stream.
type FollowResult struct {
	Payloads    []FollowPayload `json:"payloads"`
	ClientNode  string          `json:"clientNode"`
	ServerNode  string          `json:"serverNode"`
	ClientBytes int             `json:"clientBytes"`
	ServerBytes int             `json:"serverBytes"`
	PacketCount int             `json:"packetCount"`
}

func newFollowPayload(dir, hexData string) FollowPayload {
	bytes, err := hex.DecodeString(hexData)
	if err != nil {
		return FollowPayload{Dir: dir, HexData: hexData}
	}
	return FollowPayload{Dir: dir, HexData: hexData, Bytes: bytes}
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

// FollowStream extracts payloads for TCP or UDP packets selected by a display filter.
// The protocol selector is always applied in addition to displayFilter.
//
// This is a convenience wrapper that creates a temporary Session.
func FollowStream(path string, displayFilter string, proto string, opts ...Option) (*FollowResult, error) {
	return FollowStreamContext(context.Background(), path, displayFilter, proto, opts...)
}

// FollowStreamContext extracts payloads using the provided context for session
// acquisition.
func FollowStreamContext(ctx context.Context, path string, displayFilter string, proto string, opts ...Option) (*FollowResult, error) {
	s, err := OpenSessionContext(ctx, path, opts...)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return s.FollowStream(Query{Filter: displayFilter}, proto)
}

func followStreamFromConf(displayFilter string, proto string) (*FollowResult, error) {
	if proto != "tcp" && proto != "udp" {
		return nil, errors.Wrapf(ErrUnsupportedProtocol, "%q (must be \"tcp\" or \"udp\")", proto)
	}

	effectiveFilter := proto
	if displayFilter != "" {
		if err := ValidateFilter(displayFilter); err != nil {
			return nil, err
		}
		effectiveFilter = fmt.Sprintf("(%s) && (%s)", proto, displayFilter)
	}

	return getStreamPayloadsBatch(effectiveFilter, proto)
}

// =======================
// Tap Conversations / Endpoints
// =======================

// TapConversation describes one directional conversation from libwireshark's tap system.
type TapConversation struct {
	Type         string  `json:"type"`
	Addr1        string  `json:"addr1"`
	Port1        uint32  `json:"port1,omitempty"`
	Addr2        string  `json:"addr2"`
	Port2        uint32  `json:"port2,omitempty"`
	PacketsAB    uint64  `json:"packetsAB"`
	BytesAB      uint64  `json:"bytesAB"`
	PacketsBA    uint64  `json:"packetsBA"`
	BytesBA      uint64  `json:"bytesBA"`
	TotalPackets uint64  `json:"totalPackets"`
	TotalBytes   uint64  `json:"totalBytes"`
	StartTime    float64 `json:"startTime"`
	Duration     float64 `json:"duration"`
}

// TapEndpoint describes one endpoint from libwireshark's tap system.
type TapEndpoint struct {
	Type    string `json:"type"`
	Address string `json:"address"`
	Port    uint32 `json:"port,omitempty"`
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

var supportedConvTypes = map[string]bool{
	"eth": true,
	"ip":  true,
	"tcp": true,
	"udp": true,
}

// TapConversations returns Wireshark conversation statistics for the given type.
func TapConversations(path string, convType string, opts ...Option) ([]TapConversation, error) {
	return TapConversationsContext(context.Background(), path, convType, opts...)
}

// TapConversationsContext returns Wireshark conversation statistics using the
// provided context for session acquisition.
func TapConversationsContext(ctx context.Context, path string, convType string, opts ...Option) ([]TapConversation, error) {
	s, err := OpenSessionContext(ctx, path, opts...)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return s.TapConversations(convType, Query{Filter: extractFilter(opts)})
}

// TapEndpoints returns Wireshark endpoint statistics for the given type.
func TapEndpoints(path string, endpointType string, opts ...Option) ([]TapEndpoint, error) {
	return TapEndpointsContext(context.Background(), path, endpointType, opts...)
}

// TapEndpointsContext returns Wireshark endpoint statistics using the provided
// context for session acquisition.
func TapEndpointsContext(ctx context.Context, path string, endpointType string, opts ...Option) ([]TapEndpoint, error) {
	s, err := OpenSessionContext(ctx, path, opts...)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return s.TapEndpoints(endpointType, Query{Filter: extractFilter(opts)})
}

func tapConversationsFromActive(convType string, filter string) ([]TapConversation, error) {
	if !supportedConvTypes[convType] {
		return nil, errors.Wrapf(ErrUnsupportedProtocol, "conversation type %q (must be eth/ip/tcp/udp)", convType)
	}
	if filter != "" {
		if err := ValidateFilter(filter); err != nil {
			return nil, err
		}
	}

	var out []TapConversation
	var parseErr error

	globalFrameSink = func(jsonBytes []byte) bool {
		if err := sonic.Unmarshal(jsonBytes, &out); err != nil {
			parseErr = err
			return false
		}
		return true
	}
	defer cleanupGlobalState()

	cFilter := C.CString(filter)
	cType := C.CString(convType)
	defer C.free(unsafe.Pointer(cFilter))
	defer C.free(unsafe.Pointer(cType))

	if ret := C.call_get_tap_conversations_cb(cFilter, cType); ret != 0 {
		return out, errors.Wrapf(ErrReadCaptureFile, "conversation tap failed: %d", int(ret))
	}
	if parseErr != nil {
		return out, parseErr
	}
	return out, nil
}

func tapEndpointsFromActive(endpointType string, filter string) ([]TapEndpoint, error) {
	if !supportedConvTypes[endpointType] {
		return nil, errors.Wrapf(ErrUnsupportedProtocol, "endpoint type %q (must be eth/ip/tcp/udp)", endpointType)
	}
	if filter != "" {
		if err := ValidateFilter(filter); err != nil {
			return nil, err
		}
	}

	var out []TapEndpoint
	var parseErr error

	globalFrameSink = func(jsonBytes []byte) bool {
		if err := sonic.Unmarshal(jsonBytes, &out); err != nil {
			parseErr = err
			return false
		}
		return true
	}
	defer cleanupGlobalState()

	cFilter := C.CString(filter)
	cType := C.CString(endpointType)
	defer C.free(unsafe.Pointer(cFilter))
	defer C.free(unsafe.Pointer(cType))

	if ret := C.call_get_tap_endpoints_cb(cFilter, cType); ret != 0 {
		return out, errors.Wrapf(ErrReadCaptureFile, "endpoint tap failed: %d", int(ret))
	}
	if parseErr != nil {
		return out, parseErr
	}
	return out, nil
}

// =======================
// Capability detection
// =======================

// SupportsExportObjects reports whether a protocol has an export-object tap
// registered in the current libwireshark runtime.
func SupportsExportObjects(protocol string) bool {
	return supportedExportProtocols[protocol]
}

// ExportObjectProtocols returns the list of supported export-object protocols.
func ExportObjectProtocols() []string {
	return []string{"http", "smb", "tftp", "ftp-data", "imf", "dicom"}
}

// SupportsServiceResponseTimes reports whether a protocol has an SRT
// (Service Response Time) table registered in the current libwireshark
// runtime.
func SupportsServiceResponseTimes(protocol string) bool {
	return hasSrtTable(protocol)
}

// =======================
// Export Objects
// =======================

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

// =======================
// Service Response Times (SRT)
// =======================

// SRTSummary describes one procedure's response-time statistics.
type SRTSummary struct {
	Protocol  string  `json:"protocol"`
	Procedure string  `json:"procedure"`
	Calls     uint32  `json:"calls"`
	Min       float64 `json:"min"`
	Max       float64 `json:"max"`
	Avg       float64 `json:"avg"`
	Total     float64 `json:"total"`
}

func hasSrtTable(protocol string) bool {
	cProto := C.CString(protocol)
	defer C.free(unsafe.Pointer(cProto))
	return C.has_srt_table(cProto) != 0
}

// ProtocolHierarchy returns Wireshark protocol hierarchy statistics.
func ProtocolHierarchy(path string, opts ...Option) ([]ProtocolHierarchyEntry, error) {
	return ProtocolHierarchyContext(context.Background(), path, opts...)
}

// ProtocolHierarchyContext returns Wireshark protocol hierarchy statistics using
// the provided context for session acquisition.
func ProtocolHierarchyContext(ctx context.Context, path string, opts ...Option) ([]ProtocolHierarchyEntry, error) {
	s, err := OpenSessionContext(ctx, path, opts...)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return s.ProtocolHierarchy(Query{Filter: extractFilter(opts)})
}

// ServiceResponseTimes returns service response time statistics for a protocol.
func ServiceResponseTimes(path string, protocol string, opts ...Option) ([]SRTSummary, error) {
	return ServiceResponseTimesContext(context.Background(), path, protocol, opts...)
}

// ServiceResponseTimesContext returns service response time statistics using the
// provided context for session acquisition.
func ServiceResponseTimesContext(ctx context.Context, path string, protocol string, opts ...Option) ([]SRTSummary, error) {
	s, err := OpenSessionContext(ctx, path, opts...)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return s.ServiceResponseTimes(protocol, Query{Filter: extractFilter(opts)})
}

func serviceResponseTimesFromActive(protocol string, filter string) ([]SRTSummary, error) {
	if !hasSrtTable(protocol) {
		return nil, errors.Wrapf(ErrUnsupportedProtocol, "SRT protocol %q has no registered SRT table", protocol)
	}
	if filter != "" {
		if err := ValidateFilter(filter); err != nil {
			return nil, err
		}
	}

	var out []SRTSummary
	var parseErr error

	globalFrameSink = func(jsonBytes []byte) bool {
		if err := sonic.Unmarshal(jsonBytes, &out); err != nil {
			parseErr = err
			return false
		}
		return true
	}
	defer cleanupGlobalState()

	cFilter := C.CString(filter)
	cProto := C.CString(protocol)
	defer C.free(unsafe.Pointer(cFilter))
	defer C.free(unsafe.Pointer(cProto))

	if ret := C.call_get_service_response_times_cb(cFilter, cProto); ret != 0 {
		return out, errors.Wrapf(ErrReadCaptureFile, "SRT tap failed: %d", int(ret))
	}
	if parseErr != nil {
		return out, parseErr
	}
	return out, nil
}

// ProtocolHierarchyEntry statistics entry for one protocol in the protocol hierarchy
type ProtocolHierarchyEntry struct {
	Protocol string `json:"protocol"`
	Packets  uint64 `json:"packets"`
	Bytes    uint64 `json:"bytes"`
}

func protocolHierarchyFromActive(filter string) ([]ProtocolHierarchyEntry, error) {
	if filter != "" {
		if err := ValidateFilter(filter); err != nil {
			return nil, err
		}
	}

	out := make([]ProtocolHierarchyEntry, 0)
	var parseErr error

	globalFrameSink = func(jsonBytes []byte) bool {
		var entry ProtocolHierarchyEntry
		if err := sonic.Unmarshal(jsonBytes, &entry); err != nil {
			parseErr = err
			return false
		}
		out = append(out, entry)
		return true
	}
	defer cleanupGlobalState()

	cFilter := C.CString(filter)
	defer C.free(unsafe.Pointer(cFilter))

	if ret := C.call_get_proto_hierarchy_cb(cFilter); ret != 0 {
		if parseErr != nil {
			return nil, parseErr
		}
		return nil, errors.Wrap(ErrReadCaptureFile, "protocol hierarchy tap scan failed")
	}

	return out, nil
}

type IOStatBucket struct {
	Time    float64 `json:"t"`
	Packets uint64  `json:"packets"`
	Bytes   uint64  `json:"bytes"`
}

func ioStatsFromActive(filter string, intervalSecs float64) ([]IOStatBucket, error) {
	if filter != "" {
		if err := ValidateFilter(filter); err != nil {
			return nil, err
		}
	}

	out := make([]IOStatBucket, 0)
	var parseErr error

	globalFrameSink = func(jsonBytes []byte) bool {
		var bucket IOStatBucket
		if err := sonic.Unmarshal(jsonBytes, &bucket); err != nil {
			parseErr = err
			return false
		}
		out = append(out, bucket)
		return true
	}
	defer cleanupGlobalState()

	cFilter := C.CString(filter)
	defer C.free(unsafe.Pointer(cFilter))

	ret := C.call_get_io_stats_cb(cFilter, C.double(intervalSecs))
	if parseErr != nil {
		return nil, parseErr
	}
	if ret < 0 {
		if ret == -2 {
			return nil, &DisplayFilterError{Filter: filter, Message: "filter compile failed"}
		}
		return nil, errors.Wrap(ErrReadCaptureFile, "io stats scan failed")
	}

	return out, nil
}

func IOStats(path string, interval time.Duration, opts ...Option) ([]IOStatBucket, error) {
	return IOStatsContext(context.Background(), path, interval, opts...)
}

// IOStatsContext returns IO statistics using the provided context for session
// acquisition.
func IOStatsContext(ctx context.Context, path string, interval time.Duration, opts ...Option) ([]IOStatBucket, error) {
	s, err := OpenSessionContext(ctx, path, opts...)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return s.IOStats(Query{Filter: extractFilter(opts)}, interval)
}

// =======================
// Session CGo helpers
// =======================

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
