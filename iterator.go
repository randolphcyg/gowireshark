package gowireshark

/*
#include "bridge.h"
#include "offline.h"

extern int onFrameCallback(char *json, int len, int err);

static void call_get_all_frames_cb(int printCJson, char *filter) {
    get_all_frames_cb(printCJson, filter, onFrameCallback);
}

static int call_get_fields_rows_cb(char **fields, int field_count, char *filter) {
    return get_fields_rows_cb((const char **)fields, field_count, filter, onFrameCallback);
}

static int call_get_fields_rows_occurrence_cb(char **fields, int field_count, char *filter, int occurrence) {
    return get_fields_rows_occurrence_cb((const char **)fields, field_count, filter, occurrence, onFrameCallback);
}
*/
import "C"
import (
	"bufio"
	"bytes"
	"io"
	"log/slog"
	"sync"
	"unsafe"

	"github.com/pkg/errors"
)

type FrameIterator interface {
	Next() bool
	Frame() *FrameData
	Err() error
	Close() error
}

type FrameJSONIterator interface {
	Next() bool
	JSON() []byte
	Err() error
	Close() error
}

type FieldRowIterator interface {
	Next() bool
	Row() FieldRow
	Values() []string
	Err() error
	Close() error
}

type frameIterator struct {
	ch     chan []byte
	stopCh chan struct{}
	done   chan struct{}

	mu       sync.Mutex
	curFrame *FrameData
	curErr   error
	closed   bool

	parseOpts []Option
	conf      *config
	filter    string
}

func (it *frameIterator) Next() bool {
	it.mu.Lock()
	if it.closed {
		it.mu.Unlock()
		return false
	}
	it.mu.Unlock()

	jsonBytes, ok := <-it.ch
	if !ok {
		return false
	}
	frame, err := ParseFrameData(jsonBytes, it.parseOpts...)
	if err != nil {
		it.mu.Lock()
		it.curErr = err
		it.mu.Unlock()
		it.Close()
		return false
	}
	it.mu.Lock()
	it.curFrame = frame
	it.mu.Unlock()
	return true
}

func (it *frameIterator) Frame() *FrameData {
	it.mu.Lock()
	defer it.mu.Unlock()
	return it.curFrame
}

func (it *frameIterator) Err() error {
	it.mu.Lock()
	defer it.mu.Unlock()
	return it.curErr
}

func (it *frameIterator) Close() error {
	it.mu.Lock()
	if it.closed {
		it.mu.Unlock()
		return nil
	}
	it.closed = true
	it.mu.Unlock()

	close(it.stopCh)
	<-it.done

	it.mu.Lock()
	err := it.curErr
	it.mu.Unlock()
	return err
}

type frameJSONIterator struct {
	ch     chan []byte
	stopCh chan struct{}
	done   chan struct{}

	mu      sync.Mutex
	curJSON []byte
	curErr  error
	closed  bool

	conf   *config
	filter string
}

func (it *frameJSONIterator) Next() bool {
	it.mu.Lock()
	if it.closed {
		it.mu.Unlock()
		return false
	}
	it.mu.Unlock()

	jsonBytes, ok := <-it.ch
	if !ok {
		return false
	}
	it.mu.Lock()
	it.curJSON = jsonBytes
	it.mu.Unlock()
	return true
}

func (it *frameJSONIterator) JSON() []byte {
	it.mu.Lock()
	defer it.mu.Unlock()
	return it.curJSON
}

func (it *frameJSONIterator) Err() error {
	it.mu.Lock()
	defer it.mu.Unlock()
	return it.curErr
}

func (it *frameJSONIterator) Close() error {
	it.mu.Lock()
	if it.closed {
		it.mu.Unlock()
		return nil
	}
	it.closed = true
	it.mu.Unlock()

	close(it.stopCh)
	<-it.done

	it.mu.Lock()
	err := it.curErr
	it.mu.Unlock()
	return err
}

type fieldRowIterator struct {
	ch     chan []byte
	stopCh chan struct{}
	done   chan struct{}

	mu        sync.Mutex
	curRow    FieldRow
	curValues []string
	curErr    error
	closed    bool

	filter string
	fields []string
	occ    int
}

func parseFieldValues(jsonBytes []byte, fields []string) []string {
	values := make([]string, len(fields))
	for i, field := range fields {
		prefix := `"` + field + `":"`
		n := len(prefix)
		start := bytes.Index(jsonBytes, []byte(prefix))
		if start < 0 {
			tryCompact := `"` + field + `":`
			start = bytes.Index(jsonBytes, []byte(tryCompact))
			if start < 0 {
				continue
			}
			n = len(tryCompact)
		}
		start += n
		end := bytes.IndexByte(jsonBytes[start:], '"')
		if end >= 0 {
			values[i] = string(jsonBytes[start : start+end])
		}
	}
	return values
}

func (it *fieldRowIterator) Next() bool {
	it.mu.Lock()
	if it.closed {
		it.mu.Unlock()
		return false
	}
	it.mu.Unlock()

	jsonBytes, ok := <-it.ch
	if !ok {
		return false
	}
	values := parseFieldValues(jsonBytes, it.fields)

	it.mu.Lock()
	it.curValues = values
	it.curRow = nil
	it.mu.Unlock()
	return true
}

func (it *fieldRowIterator) Row() FieldRow {
	it.mu.Lock()
	defer it.mu.Unlock()
	if it.curRow != nil {
		return it.curRow
	}
	row := make(FieldRow, len(it.fields))
	for i, f := range it.fields {
		if i < len(it.curValues) && it.curValues[i] != "" {
			row[f] = it.curValues[i]
		}
	}
	it.curRow = row
	return row
}

func (it *fieldRowIterator) Values() []string {
	it.mu.Lock()
	defer it.mu.Unlock()
	return it.curValues
}

func (it *fieldRowIterator) Err() error {
	it.mu.Lock()
	defer it.mu.Unlock()
	return it.curErr
}

func (it *fieldRowIterator) Close() error {
	it.mu.Lock()
	if it.closed {
		it.mu.Unlock()
		return nil
	}
	it.closed = true
	it.mu.Unlock()

	close(it.stopCh)
	<-it.done

	it.mu.Lock()
	err := it.curErr
	it.mu.Unlock()
	return err
}

// IterFrames returns a streaming iterator over full FrameData objects.
// Each frame is fully parsed via the C proto-tree JSON path and then
// deserialised into a FrameData tree. For callers that only need raw frame
// JSON, prefer IterFrameJSON which avoids the ParseFrameData overhead.
// Both IterFrames and IterFrameJSON use the same C backend.
func (s *Session) IterFrames(q Query) (FrameIterator, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed.Load() {
		return nil, ErrSessionClosed
	}

	if q.Filter != "" {
		if err := ValidateFilter(q.Filter); err != nil {
			return nil, err
		}
	}

	ch := make(chan []byte)
	stopCh := make(chan struct{})
	done := make(chan struct{})

	it := &frameIterator{
		ch:        ch,
		stopCh:    stopCh,
		done:      done,
		parseOpts: s.parseOpts(),
		conf:      s.conf,
		filter:    q.Filter,
	}

	go func() {
		defer close(done)
		defer close(ch)
		defer func() {
			if r := recover(); r != nil {
				slog.Error("Panic in FrameIterator goroutine", "err", r)
			}
		}()

		s.mu.RLock()
		defer s.mu.RUnlock()

		if s.closed.Load() {
			return
		}

		epanMu.Lock()
		defer epanMu.Unlock()
		defer cleanupGlobalState()

		if err := s.resetReadPosition(); err != nil {
			it.mu.Lock()
			it.curErr = err
			it.mu.Unlock()
			return
		}

		globalFrameSink = func(jsonBytes []byte) bool {
			select {
			case <-stopCh:
				return false
			case ch <- jsonBytes:
				return true
			}
		}

		printCJson := 0
		if it.conf.PrintCJSON {
			printCJson = 1
		}
		cFilter := C.CString(q.Filter)
		defer C.free(unsafe.Pointer(cFilter))

		C.call_get_all_frames_cb(C.int(printCJson), cFilter)
		s.readPositionDirty.Store(true)
	}()

	return it, nil
}

func (s *Session) IterFrameJSON(q Query) (FrameJSONIterator, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed.Load() {
		return nil, ErrSessionClosed
	}

	if q.Filter != "" {
		if err := ValidateFilter(q.Filter); err != nil {
			return nil, err
		}
	}

	ch := make(chan []byte)
	stopCh := make(chan struct{})
	done := make(chan struct{})

	it := &frameJSONIterator{
		ch:     ch,
		stopCh: stopCh,
		done:   done,
		conf:   s.conf,
		filter: q.Filter,
	}

	go func() {
		defer close(done)
		defer close(ch)
		defer func() {
			if r := recover(); r != nil {
				slog.Error("Panic in FrameJSONIterator goroutine", "err", r)
			}
		}()

		s.mu.RLock()
		defer s.mu.RUnlock()

		if s.closed.Load() {
			return
		}

		epanMu.Lock()
		defer epanMu.Unlock()
		defer cleanupGlobalState()

		if err := s.resetReadPosition(); err != nil {
			it.mu.Lock()
			it.curErr = err
			it.mu.Unlock()
			return
		}

		globalFrameSink = func(jsonBytes []byte) bool {
			select {
			case <-stopCh:
				return false
			case ch <- jsonBytes:
				return true
			}
		}

		printCJson := 0
		if it.conf.PrintCJSON {
			printCJson = 1
		}
		cFilter := C.CString(q.Filter)
		defer C.free(unsafe.Pointer(cFilter))

		C.call_get_all_frames_cb(C.int(printCJson), cFilter)
		s.readPositionDirty.Store(true)
	}()

	return it, nil
}

func (s *Session) IterFieldsRows(q Query, fields []string, opts ...Option) (FieldRowIterator, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed.Load() {
		return nil, ErrSessionClosed
	}

	if err := ValidateFilter(q.Filter); err != nil {
		return nil, err
	}
	if len(fields) == 0 {
		return nil, errors.Wrap(ErrInvalidField, "at least one field is required")
	}

	conf := newConfig(opts...)
	occurrence, err := normalizeScalarFieldOccurrence(conf.FieldOccurrence)
	if err != nil {
		return nil, errors.Wrap(err, "IterFieldsRows")
	}
	occ := 0
	if occurrence == OccurrenceLast {
		occ = 1
	}

	ch := make(chan []byte)
	stopCh := make(chan struct{})
	done := make(chan struct{})

	it := &fieldRowIterator{
		ch:     ch,
		stopCh: stopCh,
		done:   done,
		filter: q.Filter,
		fields: fields,
		occ:    occ,
	}

	go func() {
		defer close(done)
		defer close(ch)
		defer func() {
			if r := recover(); r != nil {
				slog.Error("Panic in FieldRowIterator goroutine", "err", r)
			}
		}()

		s.mu.RLock()
		defer s.mu.RUnlock()

		if s.closed.Load() {
			return
		}

		epanMu.Lock()
		defer epanMu.Unlock()
		defer cleanupGlobalState()

		if err := s.resetReadPosition(); err != nil {
			it.mu.Lock()
			it.curErr = err
			it.mu.Unlock()
			return
		}

		globalFrameSink = func(jsonBytes []byte) bool {
			select {
			case <-stopCh:
				return false
			case ch <- jsonBytes:
				return true
			}
		}

		cFields := make([]*C.char, len(fields))
		for i, f := range fields {
			cFields[i] = C.CString(f)
			defer C.free(unsafe.Pointer(cFields[i]))
		}
		cFilter := C.CString(q.Filter)
		defer C.free(unsafe.Pointer(cFilter))

		ret := C.call_get_fields_rows_occurrence_cb(&cFields[0], C.int(len(fields)), cFilter, C.int(it.occ))
		if ret != 0 {
			it.mu.Lock()
			it.curErr = &DisplayFilterError{Filter: q.Filter, Message: "filter compile failed"}
			it.mu.Unlock()
		}
		s.readPositionDirty.Store(true)
	}()

	return it, nil
}

func (s *Session) WriteFieldsRows(q Query, fields []string, w io.Writer, opts ...Option) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed.Load() {
		return 0, ErrSessionClosed
	}

	if err := ValidateFilter(q.Filter); err != nil {
		return 0, err
	}
	if len(fields) == 0 {
		return 0, errors.Wrap(ErrInvalidField, "at least one field is required")
	}

	conf := newConfig(opts...)
	occurrence, err := normalizeScalarFieldOccurrence(conf.FieldOccurrence)
	if err != nil {
		return 0, errors.Wrap(err, "WriteFieldsRows")
	}
	occ := 0
	if occurrence == OccurrenceLast {
		occ = 1
	}

	bw := bufio.NewWriter(w)
	count := 0
	var writeErr error

	epanMu.Lock()
	defer epanMu.Unlock()
	defer cleanupGlobalState()

	if err := s.resetReadPosition(); err != nil {
		return 0, err
	}

	globalFrameSink = func(jsonBytes []byte) bool {
		if _, wErr := bw.Write(jsonBytes); wErr != nil {
			writeErr = wErr
			return false
		}
		if wErr := bw.WriteByte('\n'); wErr != nil {
			writeErr = wErr
			return false
		}
		count++
		return true
	}

	cFields := make([]*C.char, len(fields))
	for i, f := range fields {
		cFields[i] = C.CString(f)
		defer C.free(unsafe.Pointer(cFields[i]))
	}
	cFilter := C.CString(q.Filter)
	defer C.free(unsafe.Pointer(cFilter))

	ret := C.call_get_fields_rows_occurrence_cb(&cFields[0], C.int(len(fields)), cFilter, C.int(occ))
	s.readPositionDirty.Store(true)

	if flushErr := bw.Flush(); flushErr != nil && writeErr == nil {
		writeErr = flushErr
	}
	if ret != 0 {
		return count, &DisplayFilterError{Filter: q.Filter, Message: "filter compile failed"}
	}
	return count, writeErr
}
