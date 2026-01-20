package gowireshark

/*
#cgo pkg-config: glib-2.0
#cgo LDFLAGS: -Wl,-rpath,${SRCDIR}/libs
#cgo LDFLAGS: -L${SRCDIR}/libs -lwiretap -lwsutil -lwireshark -lpcap
#cgo CFLAGS: -I${SRCDIR}/include
#cgo CFLAGS: -I${SRCDIR}/include/wireshark
#cgo CFLAGS: -I${SRCDIR}/include/libpcap

#include "lib.h"
#include "online.h"
#include "offline.h"

// Forward declaration of the Go exported callback
extern void OnFrameCallback(char *json, int len, int err);

// Wrappers to pass the Go function pointer to C
static void call_get_frames_by_range(int start, int limit, int printCJson) {
    get_frames_by_range(start, limit, printCJson, OnFrameCallback);
}

static void call_get_all_frames_cb(int printCJson) {
    get_all_frames_cb(printCJson, OnFrameCallback);
}

static void call_get_frames_by_idxs_cb(int *idxs, int count, int printCJson) {
    get_frames_by_idxs_cb(idxs, count, printCJson, OnFrameCallback);
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
	if errCode != 0 {
		return
	}
	// Copy C string to Go string (Safe to free C string after this returns)
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
	errNo := C.init_cf(C.CString(path), C.CString(HandleConf(conf)))
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
	if srcHex != nil && C.strlen(srcHex) > 0 {
		hexData, err = ParseHexData(CChar2GoStr(srcHex))
		if err != nil {
			slog.Warn("ParseHexData error", "err", err)
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

	if parseErr != nil {
		return frames, parseErr
	}

	return frames, nil
}

// GetAllFrames fetches all frames efficiently.
func GetAllFrames(path string, opts ...Option) (frames []*FrameData, err error) {
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

	// 4. Call C function
	C.call_get_all_frames_cb(C.int(printCJson))

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

// CountFrames counts total frames using a fast I/O scan.
func CountFrames(path string) (int, error) {
	EpanMutex.Lock()
	defer EpanMutex.Unlock()

	_, err := initCapFile(path)
	if err != nil {
		return 0, err
	}

	frameCount := C.count_frames()
	if frameCount < 0 {
		return 0, fmt.Errorf("error calling C.count_frames")
	}

	return int(frameCount), nil
}

// GetFramesByPage fetches a specific page of frames using pagination.
func GetFramesByPage(path string, page, size int, opts ...Option) (frames []*FrameData, count int, err error) {
	if page < 1 {
		page = 1
	}
	if size < 1 {
		size = 10
	}

	// Fast count check
	count, err = CountFrames(path)
	if err != nil {
		return nil, 0, err
	}
	if count == 0 {
		return []*FrameData{}, 0, nil
	}

	startFrameIdx := (page-1)*size + 1
	if startFrameIdx > count {
		return []*FrameData{}, count, nil
	}

	// Global Lock & Init
	EpanMutex.Lock()
	defer EpanMutex.Unlock()

	conf, err := initCapFile(path, opts...)
	if err != nil {
		return nil, 0, err
	}

	printCJson := 0
	if conf.PrintCJson {
		printCJson = 1
	}

	// Setup Pipeline
	globalFrameChan = make(chan []byte, size)

	// Consumer
	var parseWg sync.WaitGroup
	var parseErr error
	var errMutex sync.Mutex
	resultChan := make(chan *FrameData, size)

	// Dynamic worker count
	workerNum := getOptimalWorkerNum(size)

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

	// Call C (Blocking I/O)
	C.call_get_frames_by_range(C.int(startFrameIdx), C.int(size), C.int(printCJson))

	// Cleanup
	close(globalFrameChan)
	globalFrameChan = nil

	parseWg.Wait()
	close(resultChan)

	for f := range resultChan {
		frames = append(frames, f)
	}

	if conf.Debug {
		slog.Info("Paged parsing completed", "frames", len(frames), "page", page)
	}

	slices.SortFunc(frames, func(a, b *FrameData) int {
		return a.BaseLayers.Frame.Number - b.BaseLayers.Frame.Number
	})

	if parseErr != nil {
		return frames, count, parseErr
	}

	return frames, count, nil
}
