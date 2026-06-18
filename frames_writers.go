package gowireshark

/*
#include "bridge.h"
#include "offline.h"

// Forward declaration of the Go exported callback
extern int onFrameCallback(char *json, int len, int err);

static void call_get_all_frames_cb(int printCJson, char *filter) {
    get_all_frames_cb(printCJson, filter, onFrameCallback);
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
	"sync"
	"unsafe"
)

// STABLE.
// WriteFrames dissects all selected frames and writes one raw JSON object per line to w.
// It avoids Go-side JSON unmarshal/marshal work; C produces JSON, Go copies the bytes,
// then writes NDJSON to the caller-owned writer.
// Returns the number of frames written.
func WriteFrames(path string, w io.Writer, opts ...Option) (int, error) {
	return WriteFramesContext(context.Background(), path, w, opts...)
}

// STABLE.
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

// STABLE.
// FramesPage fetches a specific page of frames using pagination.
//
// This is a convenience wrapper that creates a temporary Session.
func FramesPage(path string, page, size int, opts ...Option) ([]*FrameData, bool, error) {
	return FramesPageContext(context.Background(), path, page, size, opts...)
}

// STABLE.
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

// STABLE.
// WriteFramesPage is the NDJSON writer counterpart to FramesPage.
// It writes each selected frame's raw JSON directly to w without Go-side
// unmarshal/marshal work.
// Returns (framesWritten, hasMore, error).
func WriteFramesPage(path string, page, size int, w io.Writer, opts ...Option) (int, bool, error) {
	return WriteFramesPageContext(context.Background(), path, page, size, w, opts...)
}

// STABLE.
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
