package gowireshark

/*
#include "bridge.h"
#include "offline.h"

// Forward declaration of the Go exported callback
extern int onFrameCallback(char *json, int len, int err);

static void call_get_frames_by_idxs_cb(int *idxs, int count, int printCJson) {
    get_frames_by_idxs_cb(idxs, count, printCJson, onFrameCallback);
}

static void call_get_all_frames_cb(int printCJson, char *filter) {
    get_all_frames_cb(printCJson, filter, onFrameCallback);
}

static int call_get_frame_numbers_filtered(char *filter_str, int **numbers_out) {
    return get_frame_numbers_filtered(filter_str, numbers_out);
}

static void call_get_frames_by_range(int start, int limit, int printCJson, char *filter) {
    get_frames_by_range(start, limit, printCJson, filter, onFrameCallback);
}
*/
import "C"
import (
	"context"
	"io"
	"log/slog"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"unsafe"

	"github.com/bytedance/sonic"
	"github.com/pkg/errors"
)

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

// HexData is STABLE.
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

// STABLE.
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
