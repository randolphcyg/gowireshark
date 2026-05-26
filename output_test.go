package gowireshark

import (
	"bytes"
	"encoding/xml"
	stderrors "errors"
	"io"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/randolphcyg/gowireshark/internal/testfixture"
)

func TestSelectOutputFields(t *testing.T) {
	raw := []byte(`{"_index":"packets","layers":{"frame":{"frame.number":"7","frame.len":"128"},"ip":{"ip.src":"10.0.0.1","ip.dst":"10.0.0.2"},"tcp":{"tcp.stream":"3"}}}`)
	got, err := selectOutputFields(raw, []string{"frame.number", "ip.src", "tcp.stream", "missing.field"})
	if err != nil {
		t.Fatal(err)
	}
	if got["frame.number"] != "7" || got["ip.src"] != "10.0.0.1" || got["tcp.stream"] != "3" {
		t.Fatalf("unexpected fields: %#v", got)
	}
	if _, ok := got["missing.field"]; ok {
		t.Fatalf("missing field should be omitted: %#v", got)
	}
}

func TestWriteDissection_OutputFields_Header(t *testing.T) {
	pcap := testfixture.Pcap(t)

	var buf bytes.Buffer
	fo := FieldOutputOptions{
		Fields: []string{"frame.number", "ip.src", "ip.dst"},
		Header: true,
	}
	n, err := WriteDissection(pcap, &buf, OutputFields,
		WithFieldOutput(fo),
		WithDisplayFilter("frame.number <= 3"))
	if err != nil {
		t.Fatalf("WriteDissection: %v", err)
	}
	if n == 0 {
		t.Skip("no frames matched filter")
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) < 2 {
		t.Fatalf("expected at least header + 1 data line, got %d lines", len(lines))
	}

	if lines[0] != "frame.number\tip.src\tip.dst" {
		t.Fatalf("unexpected header: %q", lines[0])
	}

	parts := strings.Split(lines[1], "\t")
	if len(parts) != 3 {
		t.Fatalf("expected 3 tab-separated fields, got %d: %q", len(parts), lines[1])
	}
	if parts[0] != "1" {
		t.Fatalf("expected frame.number=1, got %q", parts[0])
	}
}

func TestWriteDissection_OutputFields_Separator(t *testing.T) {
	pcap := testfixture.Pcap(t)

	var buf bytes.Buffer
	fo := FieldOutputOptions{
		Fields:    []string{"frame.number", "frame.len"},
		Separator: "|",
	}
	n, err := WriteDissection(pcap, &buf, OutputFields,
		WithFieldOutput(fo),
		WithDisplayFilter("frame.number <= 2"))
	if err != nil {
		t.Fatalf("WriteDissection: %v", err)
	}
	if n == 0 {
		t.Skip("no frames matched filter")
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	parts := strings.Split(lines[0], "|")
	if len(parts) != 2 {
		t.Fatalf("expected 2 pipe-separated fields, got %d: %q", len(parts), lines[0])
	}
}

func TestWriteDissection_OutputFields_Quote(t *testing.T) {
	pcap := testfixture.Pcap(t)

	var buf bytes.Buffer
	fo := FieldOutputOptions{
		Fields: []string{"frame.number", "ip.src", "ip.dst"},
		Quote:  true,
	}
	n, err := WriteDissection(pcap, &buf, OutputFields,
		WithFieldOutput(fo),
		WithDisplayFilter("frame.number <= 1"))
	if err != nil {
		t.Fatalf("WriteDissection: %v", err)
	}
	if n == 0 {
		t.Skip("no frames matched filter")
	}

	line := strings.TrimSpace(buf.String())
	parts := strings.Split(line, "\t")
	if len(parts) != 3 {
		t.Fatalf("expected 3 tab-separated quoted fields, got %d: %q", len(parts), line)
	}
	if parts[0] != strconv.Quote(parts[0][1:len(parts[0])-1]) {
		t.Fatalf("expected fully-quoted field (strconv.Quote form), got %q", parts[0])
	}
	if !strings.HasPrefix(parts[0], "\"") || !strings.HasSuffix(parts[0], "\"") {
		t.Fatalf("expected quoted field, got %q", parts[0])
	}
	t.Logf("quote mode output line: %q", line)
}

func TestWriteDissection_OutputFields_NoFields(t *testing.T) {
	pcap := testfixture.Pcap(t)

	var buf bytes.Buffer
	_, err := WriteDissection(pcap, &buf, OutputFields,
		WithFieldOutput(FieldOutputOptions{Fields: []string{}}))
	if !stderrors.Is(err, ErrInvalidField) {
		t.Fatalf("error=%v, want ErrInvalidField", err)
	}
}

func TestWriteDissection_OutputFields_NoHeader(t *testing.T) {
	pcap := testfixture.Pcap(t)

	var buf bytes.Buffer
	fo := FieldOutputOptions{
		Fields: []string{"frame.number"},
		Header: false,
	}
	n, err := WriteDissection(pcap, &buf, OutputFields,
		WithFieldOutput(fo),
		WithDisplayFilter("frame.number <= 1"))
	if err != nil {
		t.Fatalf("WriteDissection: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 row, got %d", n)
	}
	line := strings.TrimSpace(buf.String())
	if strings.HasPrefix(line, "frame.number") {
		t.Fatalf("header should not be present when Header=false: %q", line)
	}
}

func TestWriteDissection_OutputFields_InvalidFilter(t *testing.T) {
	pcap := testfixture.Pcap(t)

	var buf bytes.Buffer
	fo := FieldOutputOptions{
		Fields: []string{"frame.number"},
		Header: true,
	}
	_, err := WriteDissection(pcap, &buf, OutputFields,
		WithFieldOutput(fo),
		WithDisplayFilter("frame.number =="))
	if err == nil {
		t.Fatal("expected error for invalid filter, got nil")
	}
	if !stderrors.Is(err, ErrInvalidDisplayFilter) {
		t.Fatalf("expected ErrInvalidDisplayFilter, got %v", err)
	}
	out := buf.String()
	if out != "" {
		t.Fatalf("expected no output on invalid filter, got: %q", out)
	}
}

func TestWriteDissection_OutputFields_WriterError(t *testing.T) {
	pcap := testfixture.Pcap(t)

	fo := FieldOutputOptions{
		Fields: []string{"frame.number"},
	}
	w := &failingWriter{}
	n, err := WriteDissection(pcap, w, OutputFields,
		WithFieldOutput(fo))
	if err == nil {
		t.Fatal("expected write error, got nil")
	}
	if n != 0 {
		t.Fatalf("expected count 0 when first write fails, got %d", n)
	}
	t.Logf("writer error: %v, count: %d", err, n)
}

func TestWriteDissection_OutputFields_OccurrenceLast(t *testing.T) {
	pcap := testfixture.Pcap(t)

	var buf bytes.Buffer
	n, err := WriteDissection(pcap, &buf, OutputFields,
		WithFieldOutput(FieldOutputOptions{
			Fields:     []string{"frame.number", "frame.protocols"},
			Occurrence: OccurrenceLast,
		}),
		WithDisplayFilter("frame.number <= 2"))
	if err != nil {
		t.Fatalf("WriteDissection occurrence last: %v", err)
	}
	if n == 0 {
		t.Fatal("expected at least one row")
	}
	if strings.TrimSpace(buf.String()) == "" {
		t.Fatal("expected output")
	}
}

func TestWriteDissection_OutputFields_RejectsOccurrenceAll(t *testing.T) {
	pcap := testfixture.Pcap(t)

	var buf bytes.Buffer
	_, err := WriteDissection(pcap, &buf, OutputFields,
		WithFieldOutput(FieldOutputOptions{
			Fields:     []string{"frame.number", "frame.protocols"},
			Occurrence: OccurrenceAll,
		}))
	if !stderrors.Is(err, ErrUnsupportedFieldOccurrence) {
		t.Fatalf("error=%v, want ErrUnsupportedFieldOccurrence", err)
	}
}

func TestWriteDissection_OutputPDML_XMLAndFilter(t *testing.T) {
	pcap := testfixture.Pcap(t)

	var buf bytes.Buffer
	n, err := WriteDissection(pcap, &buf, OutputPDML, WithDisplayFilter("frame.number <= 2"))
	if err != nil {
		t.Fatalf("WriteDissection PDML: %v", err)
	}
	if n != 2 {
		t.Fatalf("PDML count: want 2 got %d", n)
	}

	var doc struct {
		XMLName xml.Name `xml:"pdml"`
		Packets []struct {
			Protocols []struct {
				Name string `xml:"name,attr"`
			} `xml:"proto"`
		} `xml:"packet"`
	}
	if err := xml.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("PDML XML parse: %v\n%s", err, buf.String())
	}
	if doc.XMLName.Local != "pdml" {
		t.Fatalf("unexpected root: %s", doc.XMLName.Local)
	}
	if len(doc.Packets) != 2 {
		t.Fatalf("PDML packets: want 2 got %d", len(doc.Packets))
	}
}

func TestWriteDissection_OutputPSML_XMLAndFilter(t *testing.T) {
	pcap := testfixture.Pcap(t)

	var buf bytes.Buffer
	n, err := WriteDissection(pcap, &buf, OutputPSML, WithDisplayFilter("frame.number <= 1"))
	if err != nil {
		t.Fatalf("WriteDissection PSML: %v", err)
	}
	if n != 1 {
		t.Fatalf("PSML count: want 1 got %d", n)
	}

	var doc struct {
		XMLName xml.Name `xml:"psml"`
		Packets []struct {
			Section string `xml:"section"`
		} `xml:"packet"`
	}
	if err := xml.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("PSML XML parse: %v\n%s", err, buf.String())
	}
	if doc.XMLName.Local != "psml" {
		t.Fatalf("unexpected root: %s", doc.XMLName.Local)
	}
	if len(doc.Packets) != 1 {
		t.Fatalf("PSML packets: want 1 got %d", len(doc.Packets))
	}
	if doc.Packets[0].Section == "" {
		t.Fatal("expected PSML section content")
	}
}

func TestWriteDissection_OutputText_FilterAndWriterError(t *testing.T) {
	pcap := testfixture.Pcap(t)

	var buf bytes.Buffer
	n, err := WriteDissection(pcap, &buf, OutputText, WithDisplayFilter("frame.number <= 1"))
	if err != nil {
		t.Fatalf("WriteDissection text: %v", err)
	}
	if n != 1 {
		t.Fatalf("text count: want 1 got %d", n)
	}
	out := buf.String()
	if !strings.Contains(out, "Frame") {
		t.Fatalf("text output should include frame number, got: %q", out)
	}
	if !strings.Contains(out, "bytes") {
		t.Fatalf("text output should include length, got: %q", out)
	}

	n, err = WriteDissection(pcap, &failingWriter{}, OutputText, WithDisplayFilter("frame.number <= 1"))
	if err == nil {
		t.Fatal("expected writer error for OutputText")
	}
	if n != 0 {
		t.Fatalf("text writer error count: want 0 got %d", n)
	}
}

func TestWriteDissection_OutputFormats_InvalidFilterAndUnknownFormat(t *testing.T) {
	pcap := testfixture.Pcap(t)

	for _, format := range []OutputFormat{OutputPDML, OutputPSML, OutputText} {
		var buf bytes.Buffer
		_, err := WriteDissection(pcap, &buf, format, WithDisplayFilter("frame.number =="))
		if !stderrors.Is(err, ErrInvalidDisplayFilter) {
			t.Fatalf("%s invalid filter error=%v, want ErrInvalidDisplayFilter", format, err)
		}
	}

	var buf bytes.Buffer
	_, err := WriteDissection(pcap, &buf, OutputFormat("bogus"))
	if !stderrors.Is(err, ErrUnsupportedOutputFormat) {
		t.Fatalf("unknown format error=%v, want ErrUnsupportedOutputFormat", err)
	}
	var formatErr *OutputFormatError
	if !stderrors.As(err, &formatErr) {
		t.Fatalf("unknown format error=%T, want OutputFormatError", err)
	}
}

type failingWriter struct{}

func (fw *failingWriter) Write(p []byte) (int, error) {
	return 0, stderrors.New("simulated write failure")
}

func TestSessionCache_Disabled(t *testing.T) {
	pcap := testfixture.Pcap(t)

	s, err := openSession(pcap, WithSessionCache(SessionCacheOptions{Disable: true}))
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	defer s.Close()

	r1, err := s.Streams(Query{})
	if err != nil {
		t.Fatalf("first Streams: %v", err)
	}
	r2, err := s.Streams(Query{})
	if err != nil {
		t.Fatalf("second Streams: %v", err)
	}
	if len(r1) != len(r2) {
		t.Fatalf("cache-disabled results differ: %d vs %d", len(r1), len(r2))
	}
}

func TestSessionCache_PageEviction(t *testing.T) {
	pcap := testfixture.Pcap(t)

	s, err := openSession(pcap, WithSessionCache(SessionCacheOptions{MaxPages: 2}))
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	defer s.Close()

	_, _, err = s.FramesPage(Query{}, 1, 10)
	if err != nil {
		t.Fatalf("page 1: %v", err)
	}
	_, _, err = s.FramesPage(Query{}, 2, 10)
	if err != nil {
		t.Fatalf("page 2: %v", err)
	}
	_, _, err = s.FramesPage(Query{}, 3, 10)
	if err != nil {
		t.Fatalf("page 3: %v", err)
	}

	frames, _, err := s.FramesPage(Query{}, 1, 10)
	if err != nil {
		t.Fatalf("page 1 re-fetch: %v", err)
	}
	if len(frames) == 0 {
		t.Fatal("page 1 should still return results even if evicted from cache")
	}
}

func TestSession_CloseClearsCache(t *testing.T) {
	pcap := testfixture.Pcap(t)

	s, err := openSession(pcap)
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	s.Close()

	if _, err := s.Streams(Query{}); err != ErrSessionClosed {
		t.Fatalf("expected ErrSessionClosed after close, got %v", err)
	}
}

func TestSession_FrameCountCache(t *testing.T) {
	pcap := testfixture.Pcap(t)

	s, err := openSession(pcap)
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	defer s.Close()

	c1, err := s.FrameCount(Query{})
	if err != nil {
		t.Fatalf("first FrameCount: %v", err)
	}
	c2, err := s.FrameCount(Query{})
	if err != nil {
		t.Fatalf("second FrameCount: %v", err)
	}
	if c1 != c2 {
		t.Fatalf("cached count differs: %d vs %d", c1, c2)
	}
}

func TestSessionCache_PageOrderNoDuplicates(t *testing.T) {
	pcap := testfixture.Pcap(t)

	s, err := openSession(pcap, WithSessionCache(SessionCacheOptions{MaxPages: 3}))
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	defer s.Close()

	s.cache.mu.Lock()
	initialLen := len(s.cache.pageOrder)
	s.cache.mu.Unlock()

	_, _, err = s.FramesPage(Query{}, 1, 10)
	if err != nil {
		t.Fatalf("page 1: %v", err)
	}
	_, _, err = s.FramesPage(Query{}, 2, 10)
	if err != nil {
		t.Fatalf("page 2: %v", err)
	}

	s.cache.mu.Lock()
	afterTwoPages := len(s.cache.pageOrder)
	s.cache.mu.Unlock()

	if afterTwoPages != initialLen+2 {
		t.Fatalf("expected pageOrder +2 after two unique pages, got initial=%d after=%d", initialLen, afterTwoPages)
	}

	_, _, err = s.FramesPage(Query{}, 1, 10)
	if err != nil {
		t.Fatalf("page 1 duplicate: %v", err)
	}

	s.cache.mu.Lock()
	afterDuplicate := len(s.cache.pageOrder)
	s.cache.mu.Unlock()

	if afterDuplicate > afterTwoPages {
		t.Fatalf("duplicate page request grew pageOrder: %d -> %d", afterTwoPages, afterDuplicate)
	}
}

func TestSessionCache_MaxPagesObserved(t *testing.T) {
	pcap := testfixture.Pcap(t)

	s, err := openSession(pcap, WithSessionCache(SessionCacheOptions{MaxPages: 2}))
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	defer s.Close()

	for pg := 1; pg <= 5; pg++ {
		_, _, err := s.FramesPage(Query{}, pg, 10)
		if err != nil {
			t.Fatalf("page %d: %v", pg, err)
		}
	}

	s.cache.mu.Lock()
	pagesLen := len(s.cache.pages)
	s.cache.mu.Unlock()

	if pagesLen > 2 {
		t.Fatalf("expected at most 2 cached pages after MaxPages=2, got %d", pagesLen)
	}

	pg1Frames, _, err := s.FramesPage(Query{}, 1, 10)
	if err != nil {
		t.Fatalf("page 1 re-fetch after eviction: %v", err)
	}
	if len(pg1Frames) == 0 {
		t.Fatal("page 1 should return frames even if evicted from cache")
	}
}

func TestSession_FollowStream_OverSizeNotCached(t *testing.T) {
	pcap := testfixture.Pcap(t)

	s, err := openSession(pcap, WithSessionCache(SessionCacheOptions{MaxFollowBytes: 1}))
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	defer s.Close()

	result, err := s.FollowStream(Query{}, "tcp")
	if err != nil {
		t.Fatalf("FollowStream: %v", err)
	}
	if result == nil {
		t.Skip("no TCP streams in test pcap")
	}

	totalBytes := result.ClientBytes + result.ServerBytes
	if totalBytes == 0 {
		t.Skip("TCP stream has no payload bytes to test MaxFollowBytes cache skip")
	}
	t.Logf("follow result: %d client bytes + %d server bytes = %d total",
		result.ClientBytes, result.ServerBytes, totalBytes)

	result2, err := s.FollowStream(Query{}, "tcp")
	if err != nil {
		t.Fatalf("second FollowStream: %v", err)
	}
	if result2.PacketCount != result.PacketCount {
		t.Fatalf("follow results differ when cache should skip: first=%d second=%d",
			result.PacketCount, result2.PacketCount)
	}
}

func TestSession_WriteDissection_ConcurrentCloseNoDeadlock(t *testing.T) {
	pcap := testfixture.Pcap(t)

	for _, format := range []OutputFormat{OutputJSON, OutputPDML} {
		t.Run(string(format), func(t *testing.T) {
			s, err := openSession(pcap)
			if err != nil {
				t.Fatalf("OpenSession: %v", err)
			}

			var wg sync.WaitGroup
			started := make(chan struct{})
			writeDone := make(chan struct{})

			wg.Add(1)
			go func() {
				defer wg.Done()
				close(started)
				_, werr := s.WriteDissection(io.Discard, format, Query{})
				if werr != nil && !stderrors.Is(werr, ErrSessionClosed) {
					t.Logf("WriteDissection(%s) returned: %v", format, werr)
				}
				close(writeDone)
			}()

			<-started
			time.Sleep(50 * time.Millisecond)

			closeErr := s.Close()
			if closeErr != nil {
				t.Logf("Close: %v", closeErr)
			}

			select {
			case <-writeDone:
			case <-time.After(30 * time.Second):
				t.Fatal("WriteDissection did not return within 30s — probable deadlock")
			}

			wg.Wait()
		})
	}
}
