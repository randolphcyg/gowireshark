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
*/
import "C"
import (
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

// onFrameCallback
// This function is called from C. It copies the JSON string to Go memory and pushes it to the channel.
//
//export onFrameCallback
func onFrameCallback(jsonStr *C.char, length C.int, errCode C.int) C.int {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("Panic in onFrameCallback", "err", r)
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

// Version returns the version of the EPAN module.
func Version() string {
	return C.GoString((*C.char)(C.epan_get_version()))
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

	cPath := C.CString(path)
	cOptions := C.CString(marshalConfig(conf))
	defer C.free(unsafe.Pointer(cPath))
	defer C.free(unsafe.Pointer(cOptions))

	errNo := C.init_cf(cPath, cOptions)
	if errNo != 0 {
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

// HexDataByIndex retrieves hex dump for a specific frame index.
func HexDataByIndex(path string, frameIdx int, opts ...Option) (hexData *HexData, err error) {
	epanMu.Lock()
	defer epanMu.Unlock()

	_, err = initCapFile(path, opts...)
	if err != nil {
		return
	}

	srcHex := C.get_specific_frame_hex_data(C.int(frameIdx))
	if srcHex != nil {
		defer C.free(unsafe.Pointer(srcHex))
		if C.strlen(srcHex) > 0 {
			hexData, err = parseHexData(cString(srcHex))
		}
	}
	return
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

	var layerErrors []error

	// Parse base layers — each method returns concrete type, nil on not-found
	if v, e := frame.Layers.Frame(); e == nil {
		frame.BaseLayers.Frame = v
	} else if !errors.Is(e, ErrLayerNotFound) {
		layerErrors = append(layerErrors, e)
	}

	if v, e := frame.Layers.WSCol(); e == nil {
		frame.BaseLayers.WSCol = v
	} else if !errors.Is(e, ErrLayerNotFound) {
		layerErrors = append(layerErrors, e)
	}

	if v, e := frame.Layers.ETH(); e == nil {
		frame.BaseLayers.ETH = v
	} else if !errors.Is(e, ErrLayerNotFound) {
		layerErrors = append(layerErrors, e)
	}

	if v, e := frame.Layers.IP(); e == nil {
		frame.BaseLayers.IP = v
	} else if !errors.Is(e, ErrLayerNotFound) {
		layerErrors = append(layerErrors, e)
	}

	if v, e := frame.Layers.UDP(); e == nil {
		frame.BaseLayers.UDP = v
	} else if !errors.Is(e, ErrLayerNotFound) {
		layerErrors = append(layerErrors, e)
	}

	if v, e := frame.Layers.TCP(); e == nil {
		frame.BaseLayers.TCP = v
	} else if !errors.Is(e, ErrLayerNotFound) {
		layerErrors = append(layerErrors, e)
	}

	if v, e := frame.Layers.HTTP(); e == nil {
		frame.BaseLayers.HTTP = v
	} else if !errors.Is(e, ErrLayerNotFound) {
		layerErrors = append(layerErrors, e)
	}

	if v, e := frame.Layers.DNS(); e == nil {
		frame.BaseLayers.DNS = v
	} else if !errors.Is(e, ErrLayerNotFound) {
		layerErrors = append(layerErrors, e)
	}

	conf := newConfig(opts...)
	if conf.Registry != nil && conf.Registry.Len() > 0 {
		if customResults := conf.Registry.ParseAll(frame.Layers); len(customResults) > 0 {
			frame.CustomLayers = customResults
		}
	}

	if len(layerErrors) > 0 {
		frameNum := 0
		if frame.BaseLayers.Frame != nil {
			frameNum = frame.BaseLayers.Frame.Number
		}
		return frame, errors.Errorf("frame:%d errors:%v", frameNum, layerErrors)
	}

	return frame, nil
}

// FrameByIndex gets a single frame by its 1-based index.
func FrameByIndex(path string, frameIdx int, opts ...Option) (frameData *FrameData, err error) {
	if frameIdx < 1 {
		return nil, errors.New("frameIdx must be >= 1")
	}

	epanMu.Lock()
	defer epanMu.Unlock()

	conf, err := initCapFile(path, opts...)
	if err != nil {
		return
	}

	printCJson := 0
	if conf.PrintCJSON {
		printCJson = 1
	}

	srcFrame := C.proto_tree_in_json(C.int(frameIdx), C.int(printCJson))
	if srcFrame == nil || C.strlen(srcFrame) == 0 {
		if srcFrame != nil {
			C.free_c_string(srcFrame)
		}
		return nil, ErrFrameNotFound
	}
	defer C.free_c_string(srcFrame)

	frameData, err = ParseFrameData([]byte(cString(srcFrame)), opts...)
	return
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

// FramesByIndices fetches specific frames efficiently using a single pass.
func FramesByIndices(path string, frameIdxs []int, opts ...Option) (frames []*FrameData, err error) {
	if len(frameIdxs) == 0 {
		return []*FrameData{}, nil
	}

	epanMu.Lock()
	defer epanMu.Unlock()

	conf, err := initCapFile(path, opts...)
	if err != nil {
		return nil, err
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
		return []*FrameData{}, nil
	}

	// 2. Setup channel
	globalFrameChan = make(chan []byte, len(frameIdxs))

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
			for jsonStr := range globalFrameChan {
				frame, e := ParseFrameData(jsonStr, opts...)
				if e != nil {
					if !conf.IgnoreErrors {
						errMutex.Lock()
						parseErr = e
						errMutex.Unlock()
					} else {
						slog.Warn("FramesByIndices Parse Error", "err", e)
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
	close(globalFrameChan)
	globalFrameChan = nil

	parseWg.Wait()
	close(resultChan)

	for f := range resultChan {
		frames = append(frames, f)
	}

	sortFrames(frames)

	if parseErr != nil {
		return frames, parseErr
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
		return fmt.Errorf("Syntax error in display filter: %s", cString(cErrMsg))
	}
	return nil
}

// FrameCount returns the number of frames selected by the supplied options.
// This is a convenience wrapper that creates a temporary Session.
func FrameCount(path string, opts ...Option) (int, error) {
	s, err := OpenSession(path, opts...)
	if err != nil {
		return 0, err
	}
	defer s.Close()
	return s.FrameCount(Query{Filter: extractFilter(opts)})
}

func extractFilter(opts []Option) string {
	return newConfig(opts...).DisplayFilter
}

// Frames fetches all frames efficiently.
func Frames(path string, opts ...Option) (frames []*FrameData, err error) {
	frames = make([]*FrameData, 0)

	epanMu.Lock()
	defer epanMu.Unlock()

	conf, err := initCapFile(path, opts...)
	if err != nil {
		return nil, err
	}

	if conf.DisplayFilter != "" {
		if err := ValidateFilter(conf.DisplayFilter); err != nil {
			return frames, err
		}
	}

	printCJson := 0
	if conf.PrintCJSON {
		printCJson = 1
	}

	// 1. Setup channel
	globalFrameChan = make(chan []byte, 1000)

	// 2. Start concurrent parsers
	var parseWg sync.WaitGroup
	var parseErr error
	var errMutex sync.Mutex
	resultChan := make(chan *FrameData, 1000)

	workerNum := runtime.NumCPU()
	if workerNum < 1 {
		workerNum = 1
	}

	parseWg.Add(workerNum)
	for i := 0; i < workerNum; i++ {
		go func() {
			defer parseWg.Done()
			for jsonStr := range globalFrameChan {
				frame, e := ParseFrameData(jsonStr, opts...)
				if e != nil {
					if !conf.IgnoreErrors {
						errMutex.Lock()
						parseErr = e
						errMutex.Unlock()
					}
					continue
				}
				resultChan <- frame
			}
		}()
	}

	// 3. Collector
	doneChan := make(chan struct{})
	go func() {
		for f := range resultChan {
			frames = append(frames, f)
		}
		close(doneChan)
	}()

	cFilter := C.CString(conf.DisplayFilter)
	defer C.free(unsafe.Pointer(cFilter))

	// 4. Call C function
	C.call_get_all_frames_cb(C.int(printCJson), cFilter)

	// 5. Cleanup
	close(globalFrameChan)
	globalFrameChan = nil

	// 6. Wait for workers
	parseWg.Wait()
	close(resultChan)
	<-doneChan

	// 7. Sort results
	sortFrames(frames)

	if conf.Debug {
		slog.Info("Frames Dissect end", "PCAP_FILE", path, "COUNT", len(frames))
	}

	if parseErr != nil {
		return frames, parseErr
	}

	return frames, nil
}

// WriteFrames dissects all selected frames and writes one raw JSON object per line to w.
// It avoids Go-side JSON unmarshal/marshal work; C produces JSON, Go copies the bytes,
// then writes NDJSON to the caller-owned writer.
// Returns the number of frames written.
func WriteFrames(path string, w io.Writer, opts ...Option) (count int, err error) {
	if !fileExists(path) {
		return 0, errors.Wrap(ErrFileNotFound, path)
	}

	epanMu.Lock()
	defer epanMu.Unlock()

	conf, err := initCapFile(path, opts...)
	if err != nil {
		return 0, err
	}

	if conf.DisplayFilter != "" {
		if err := ValidateFilter(conf.DisplayFilter); err != nil {
			return 0, err
		}
	}

	printCJson := 0
	if conf.PrintCJSON {
		printCJson = 1
	}

	var writeErr error
	globalFrameSink = func(jsonBytes []byte) bool {
		if _, e := w.Write(jsonBytes); e != nil {
			writeErr = e
			return false
		}
		if _, e := w.Write([]byte("\n")); e != nil {
			writeErr = e
			return false
		}
		count++
		return true
	}
	defer func() { globalFrameSink = nil }()

	cFilter := C.CString(conf.DisplayFilter)
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
	s, err := OpenSession(path, opts...)
	if err != nil {
		return nil, false, err
	}
	defer s.Close()
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

	globalFrameChan = make(chan []byte, fetchSize)

	var parseWg sync.WaitGroup
	var parseErr error
	var errMutex sync.Mutex
	resultChan := make(chan *FrameData, fetchSize)

	workerNum := getOptimalWorkerNum(fetchSize)

	parseWg.Add(workerNum)
	for i := 0; i < workerNum; i++ {
		go func() {
			defer parseWg.Done()
			for jsonStr := range globalFrameChan {
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

	close(globalFrameChan)
	globalFrameChan = nil

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
func WriteFramesPage(path string, page, size int, w io.Writer, opts ...Option) (count int, hasMore bool, err error) {
	if page < 1 {
		page = 1
	}
	if size < 1 {
		size = 20
	}

	fetchSize := size + 1
	startFrameIdx := (page-1)*size + 1

	epanMu.Lock()
	defer epanMu.Unlock()

	conf, err := initCapFile(path, opts...)
	if err != nil {
		return 0, false, err
	}

	if conf.DisplayFilter != "" {
		if err := ValidateFilter(conf.DisplayFilter); err != nil {
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
		if _, e := w.Write(jsonBytes); e != nil {
			writeErr = e
			return false
		}
		if _, e := w.Write([]byte("\n")); e != nil {
			writeErr = e
			return false
		}
		count++
		return true
	}
	defer func() { globalFrameSink = nil }()

	cFilter := C.CString(conf.DisplayFilter)
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
	s, err := OpenSession(path, opts...)
	if err != nil {
		return err
	}
	defer s.Close()
	return s.WalkFrames(Query{Filter: extractFilter(opts)}, walkFn)
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
	defer func() { globalFrameSink = nil }()

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
	s, err := OpenSession(path, opts...)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	return s.FollowStream(Query{Filter: displayFilter}, proto)
}

func followStreamFromConf(displayFilter string, proto string) (*FollowResult, error) {
	if proto != "tcp" && proto != "udp" {
		return nil, errors.Errorf("unsupported protocol: %q (must be \"tcp\" or \"udp\")", proto)
	}

	effectiveFilter := proto
	if displayFilter != "" {
		if err := ValidateFilter(displayFilter); err != nil {
			return nil, err
		}
		effectiveFilter = fmt.Sprintf("(%s) && (%s)", proto, displayFilter)
	}

	globalFrameChan = make(chan []byte, 1000)
	resChan := make(chan *FollowResult, 1)

	go func() {
		result := &FollowResult{
			ClientNode: "Client",
			ServerNode: "Server",
		}
		clientPort := -1
		currentDir := ""

		var currentBuilder strings.Builder

		for jsonStr := range globalFrameChan {
			var fastFrame fastFollowPayload

			if err := sonic.Unmarshal(jsonStr, &fastFrame); err != nil {
				continue
			}

			if fastFrame.Summary {
				result.PacketCount = fastFrame.MatchedCount
				continue
			}

			if fastFrame.Payload == "" {
				continue
			}

			if clientPort == -1 && fastFrame.SrcPort != 0 {
				clientPort = fastFrame.SrcPort
				result.ClientNode = fmt.Sprintf("%s:%d", fastFrame.Src, fastFrame.SrcPort)
				result.ServerNode = fmt.Sprintf("%s:%d", fastFrame.Dst, fastFrame.DstPort)
			}

			dir := "server"
			if fastFrame.SrcPort == clientPort {
				dir = "client"
			}

			bytesLen := len(fastFrame.Payload) / 2
			if dir == "client" {
				result.ClientBytes += bytesLen
			} else {
				result.ServerBytes += bytesLen
			}

			if currentDir == "" {
				currentDir = dir
				currentBuilder.WriteString(fastFrame.Payload)
			} else if currentDir == dir {
				currentBuilder.WriteString(fastFrame.Payload)
			} else {
				result.Payloads = append(result.Payloads, newFollowPayload(currentDir, currentBuilder.String()))
				currentDir = dir
				currentBuilder.Reset()
				currentBuilder.WriteString(fastFrame.Payload)
			}
		}

		if currentDir != "" {
			result.Payloads = append(result.Payloads, newFollowPayload(currentDir, currentBuilder.String()))
		}
		if len(result.Payloads) == 0 {
			result.Payloads = append(result.Payloads, FollowPayload{Dir: "client", HexData: ""})
		}

		resChan <- result
	}()

	cFilter := C.CString(effectiveFilter)
	cProto := C.CString(proto)
	defer C.free(unsafe.Pointer(cFilter))
	defer C.free(unsafe.Pointer(cProto))

	C.call_get_stream_payloads_cb(cFilter, cProto)

	close(globalFrameChan)
	globalFrameChan = nil

	res := <-resChan
	return res, nil
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
