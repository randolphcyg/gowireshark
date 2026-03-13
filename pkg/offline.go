package pkg

/*
#cgo pkg-config: glib-2.0
#include "lib.h"
#include "online.h"
#include "offline.h"

// Forward declaration of the Go exported callback
extern void OnFrameCallback(char *json, int len, int err);

// Wrappers to pass the Go function pointer to C
static void call_get_frames_by_range(int start, int limit, int printCJson, char *filter) {
    get_frames_by_range(start, limit, printCJson, filter, OnFrameCallback);
}

static void call_get_all_frames_cb(int printCJson, char *filter) {
    get_all_frames_cb(printCJson, filter, OnFrameCallback);
}

static void call_get_frames_by_idxs_cb(int *idxs, int count, int printCJson) {
    get_frames_by_idxs_cb(idxs, count, printCJson, OnFrameCallback);
}

static void call_get_stream_payloads_cb(char *filter, char *proto) {
    get_stream_payloads_cb(filter, proto, OnFrameCallback);
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

// Global channel for bridging C callbacks to Go consumers.
// Protected by EpanMutex implicitly as only one dissection task runs at a time.
var globalFrameChan chan []byte

// OnFrameCallback
// This function is called from C. It copies the JSON string to Go memory and pushes it to the channel.
//
//export OnFrameCallback
func OnFrameCallback(jsonStr *C.char, length C.int, errCode C.int) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("Panic in OnFrameCallback", "err", r)
		}
	}()

	if errCode != 0 {
		return
	}
	if jsonStr == nil || length <= 0 {
		return
	}

	goBytes := C.GoBytes(unsafe.Pointer(jsonStr), length)
	if globalFrameChan != nil {
		globalFrameChan <- goBytes
	}
}

var (
	ErrFileNotFound    = errors.New("cannot open file, no such file")
	ErrReadFile        = errors.New("occur error when read file ")
	ErrFromCLogic      = errors.New("run c logic occur error")
	ErrParseDissectRes = errors.New("fail to parse DissectRes")
	ErrFrameIsBlank    = errors.New("frame data is blank")
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

// EpanMutex ensures thread safety for libwireshark's global state.
var EpanMutex = &sync.Mutex{}

// init initializes the Wireshark environment once on startup.
func init() {
	if !C.init_env() {
		panic("failed to initialize wireshark env")
	}
}

// IsFileExist check if a file path exists.
func IsFileExist(path string) bool {
	_, err := os.Lstat(path)
	return !os.IsNotExist(err)
}

// CChar2GoStr converts a C char* to a Go string.
func CChar2GoStr(src *C.char) string {
	return C.GoStringN(src, C.int(C.strlen(src)))
}

// EpanVersion returns the version of the EPAN module.
func EpanVersion() string {
	return C.GoString((*C.char)(C.epan_get_version()))
}

// EpanPluginsSupported checks plugin support status.
func EpanPluginsSupported() int {
	return int(C.epan_plugins_supported())
}

// initCapFile initializes the capture file structure in C.
func initCapFile(path string, opts ...Option) (conf *Conf, err error) {
	if !IsFileExist(path) {
		err = errors.Wrap(ErrFileNotFound, path)
		return
	}

	conf = NewConfig(opts...)

	cPath := C.CString(path)
	cOptions := C.CString(HandleConf(conf))
	defer C.free(unsafe.Pointer(cPath))
	defer C.free(unsafe.Pointer(cOptions))

	errNo := C.init_cf(cPath, cOptions)
	if errNo != 0 {
		err = errors.Wrap(ErrReadFile, strconv.Itoa(int(errNo)))
		return
	}

	return
}

// PrintAllFrames dissects and prints all frames to stdout.
func PrintAllFrames(path string) (err error) {
	EpanMutex.Lock()
	defer EpanMutex.Unlock()

	_, err = initCapFile(path)
	if err != nil {
		return
	}
	C.print_all_frame()
	return
}

// HexData represents the hex dump format.
type HexData struct {
	Offset []string `json:"offset"`
	Hex    []string `json:"hex"`
	Ascii  []string `json:"ascii"`
}

// ParseHexData unmarshal JSON hex data.
func ParseHexData(src string) (hexData *HexData, err error) {
	err = sonic.Unmarshal([]byte(src), &hexData)
	return
}

// GetHexDataByIdx retrieves hex dump for a specific frame index.
func GetHexDataByIdx(path string, frameIdx int, opts ...Option) (hexData *HexData, err error) {
	EpanMutex.Lock()
	defer EpanMutex.Unlock()

	_, err = initCapFile(path, opts...)
	if err != nil {
		return
	}

	srcHex := C.get_specific_frame_hex_data(C.int(frameIdx))
	if srcHex != nil {
		defer C.free(unsafe.Pointer(srcHex))
		if C.strlen(srcHex) > 0 {
			hexData, err = ParseHexData(CChar2GoStr(srcHex))
		}
	}
	return
}

// ParseFrameData parses the JSON representation of a dissected frame.
func ParseFrameData(src []byte) (frame *FrameData, err error) {
	if len(src) == 0 {
		return nil, errors.New("empty input data")
	}

	err = sonic.Unmarshal(src, &frame)
	if err != nil {
		return nil, ErrParseDissectRes
	}

	var layerErrors []error
	parseLayer := func(layerFunc func() (any, error), setLayerFunc func(any)) {
		val, err := layerFunc()
		if err == nil {
			setLayerFunc(val)
		} else if !errors.Is(err, ErrLayerNotFound) {
			layerErrors = append(layerErrors, err)
		}
	}

	// Parse specific layers
	parseLayer(frame.Layers.WsCol, func(v any) { frame.BaseLayers.WsCol = v.(*WsCol) })
	parseLayer(frame.Layers.Frame, func(v any) { frame.BaseLayers.Frame = v.(*Frame) })
	parseLayer(frame.Layers.Eth, func(v any) { frame.BaseLayers.Eth = v.(*Eth) })
	parseLayer(frame.Layers.Ip, func(v any) { frame.BaseLayers.Ip = v.(*Ip) })
	parseLayer(frame.Layers.Udp, func(v any) { frame.BaseLayers.Udp = v.(*Udp) })
	parseLayer(frame.Layers.Tcp, func(v any) { frame.BaseLayers.Tcp = v.(*Tcp) })
	parseLayer(frame.Layers.Http, func(v any) { frame.BaseLayers.Http = v.([]*Http) })
	parseLayer(frame.Layers.Dns, func(v any) { frame.BaseLayers.Dns = v.(*Dns) })

	if len(layerErrors) > 0 {
		return frame, errors.Errorf("frame:%d errors:%v", frame.BaseLayers.Frame.Number, layerErrors)
	}

	return frame, nil
}

// GetFrameByIdx gets a single frame.
func GetFrameByIdx(path string, frameIdx int, opts ...Option) (frameData *FrameData, err error) {
	EpanMutex.Lock()
	defer EpanMutex.Unlock()

	conf, err := initCapFile(path, opts...)
	if err != nil {
		return
	}

	printCJson := 0
	if conf.PrintCJson {
		printCJson = 1
	}

	counter := 0
	for {
		counter++
		if counter < frameIdx && frameIdx != counter {
			continue
		}

		srcFrame := C.proto_tree_in_json(C.int(counter), C.int(printCJson))
		if srcFrame != nil {
			defer C.free_c_string(srcFrame)
			if C.strlen(srcFrame) == 0 {
				return frameData, ErrFrameIsBlank
			}
		}

		// unmarshal dissect result
		frameData, err = ParseFrameData([]byte(CChar2GoStr(srcFrame)))
		if err != nil {
			slog.Warn("GetFrameByIdx:", "ParseFrameData", err)
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

// GetFramesByIdxs fetches specific frames efficiently using a single pass.
func GetFramesByIdxs(path string, frameIdxs []int, opts ...Option) (frames []*FrameData, err error) {
	if len(frameIdxs) == 0 {
		return []*FrameData{}, nil
	}

	EpanMutex.Lock()
	defer EpanMutex.Unlock()

	conf, err := initCapFile(path, opts...)
	if err != nil {
		return nil, err
	}

	printCJson := 0
	if conf.PrintCJson {
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
				frame, e := ParseFrameData(jsonStr)
				if e != nil {
					if !conf.IgnoreError {
						errMutex.Lock()
						parseErr = e
						errMutex.Unlock()
					} else {
						slog.Warn("GetFramesByIdxs Parse Error", "err", e)
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

	slices.SortFunc(frames, func(a, b *FrameData) int {
		return a.BaseLayers.Frame.Number - b.BaseLayers.Frame.Number
	})

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
		return fmt.Errorf("Syntax error in display filter: %s", CChar2GoStr(cErrMsg))
	}
	return nil
}

// GetAllFrames fetches all frames efficiently.
func GetAllFrames(path string, opts ...Option) (frames []*FrameData, err error) {
	frames = make([]*FrameData, 0)

	EpanMutex.Lock()
	defer EpanMutex.Unlock()

	conf, err := initCapFile(path, opts...)
	if err != nil {
		return nil, err
	}

	if conf.BpfFilter != "" {
		if err := ValidateFilter(conf.BpfFilter); err != nil {
			return frames, err
		}
	}

	printCJson := 0
	if conf.PrintCJson {
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
				frame, e := ParseFrameData(jsonStr)
				if e != nil {
					if !conf.IgnoreError {
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

	cFilter := C.CString(conf.BpfFilter)
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
	slices.SortFunc(frames, func(a, b *FrameData) int {
		return a.BaseLayers.Frame.Number - b.BaseLayers.Frame.Number
	})

	if conf.Debug {
		slog.Info("GetAllFrames Dissect end", "PCAP_FILE", path, "COUNT", len(frames))
	}

	if parseErr != nil {
		return frames, parseErr
	}

	return frames, nil
}

// GetFramesByPage fetches a specific page of frames using pagination.
func GetFramesByPage(path string, page, size int, opts ...Option) (frames []*FrameData, hasMore bool, err error) {
	frames = make([]*FrameData, 0)

	if page < 1 {
		page = 1
	}
	if size < 1 {
		size = 10
	}

	fetchSize := size + 1
	startFrameIdx := (page-1)*size + 1

	// Global Lock & Init
	EpanMutex.Lock()
	defer EpanMutex.Unlock()

	conf, err := initCapFile(path, opts...)
	if err != nil {
		return frames, false, err
	}

	// 1. Validate BPF filter
	if conf.BpfFilter != "" {
		if err := ValidateFilter(conf.BpfFilter); err != nil {
			return frames, false, err
		}
	}

	printCJson := 0
	if conf.PrintCJson {
		printCJson = 1
	}

	// Setup Pipeline
	globalFrameChan = make(chan []byte, fetchSize)

	// Consumer
	var parseWg sync.WaitGroup
	var parseErr error
	var errMutex sync.Mutex
	resultChan := make(chan *FrameData, fetchSize)

	// Dynamic worker count
	workerNum := getOptimalWorkerNum(fetchSize)

	parseWg.Add(workerNum)
	for i := 0; i < workerNum; i++ {
		go func() {
			defer parseWg.Done()
			for jsonStr := range globalFrameChan {
				f, e := ParseFrameData(jsonStr)
				if e != nil {
					if !conf.IgnoreError {
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

	cFilter := C.CString(conf.BpfFilter)
	defer C.free(unsafe.Pointer(cFilter))

	// Call C (Blocking I/O)
	C.call_get_frames_by_range(C.int(startFrameIdx), C.int(fetchSize), C.int(printCJson), cFilter)

	// Cleanup
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

	slices.SortFunc(frames, func(a, b *FrameData) int {
		return a.BaseLayers.Frame.Number - b.BaseLayers.Frame.Number
	})

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

// =======================
// Stream Tracking
// =======================

type StreamPayload struct {
	Dir     string `json:"dir"`
	HexData string `json:"hexData"`
}

type StreamResult struct {
	Payloads    []StreamPayload `json:"payloads"`
	ClientNode  string          `json:"clientNode"`
	ServerNode  string          `json:"serverNode"`
	ClientBytes int             `json:"clientBytes"`
	ServerBytes int             `json:"serverBytes"`
	PacketCount int             `json:"packetCount"`
}

type FastStreamPayload struct {
	Summary      bool   `json:"_summary"`
	MatchedCount int    `json:"matched_count"`
	Src          string `json:"src"`
	Dst          string `json:"dst"`
	SrcPort      int    `json:"srcport"`
	DstPort      int    `json:"dstport"`
	Payload      string `json:"payload"`
}

// GetStreamData With streaming read, the frame object is dropped immediately after the Payload is extracted
func GetStreamData(path string, filter string, proto string, opts ...Option) (*StreamResult, error) {
	EpanMutex.Lock()
	defer EpanMutex.Unlock()

	_, err := initCapFile(path, opts...)
	if err != nil {
		return nil, err
	}

	if filter != "" {
		if err := ValidateFilter(filter); err != nil {
			return nil, err
		}
	}

	globalFrameChan = make(chan []byte, 1000)
	resChan := make(chan *StreamResult, 1)

	go func() {
		result := &StreamResult{
			ClientNode: "Client",
			ServerNode: "Server",
		}
		clientPort := -1
		currentDir := ""

		var currentBuilder strings.Builder

		for jsonStr := range globalFrameChan {
			var fastFrame FastStreamPayload

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
				result.Payloads = append(result.Payloads, StreamPayload{Dir: currentDir, HexData: currentBuilder.String()})
				currentDir = dir
				currentBuilder.Reset()
				currentBuilder.WriteString(fastFrame.Payload)
			}
		}

		if currentDir != "" {
			result.Payloads = append(result.Payloads, StreamPayload{Dir: currentDir, HexData: currentBuilder.String()})
		}
		if len(result.Payloads) == 0 {
			result.Payloads = append(result.Payloads, StreamPayload{Dir: "client", HexData: ""})
		}

		resChan <- result
	}()

	cFilter := C.CString(filter)
	cProto := C.CString(proto)
	defer C.free(unsafe.Pointer(cFilter))
	defer C.free(unsafe.Pointer(cProto))

	C.call_get_stream_payloads_cb(cFilter, cProto)

	close(globalFrameChan)
	globalFrameChan = nil

	res := <-resChan
	return res, nil
}
