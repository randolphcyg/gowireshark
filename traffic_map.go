package gowireshark

import (
	"context"
	"fmt"
	"hash/fnv"
	"slices"
	"strconv"
	"strings"
	"time"
)

// StreamSummary is STABLE.
// StreamSummary describes one TCP or UDP stream observed in a capture.
type StreamSummary struct {
	Protocol       string   `json:"protocol"`
	ConversationID int      `json:"conversationId"`
	StreamID       int      `json:"streamId"`
	SrcAddr        string   `json:"srcAddr"`
	SrcPort        int      `json:"srcPort"`
	DstAddr        string   `json:"dstAddr"`
	DstPort        int      `json:"dstPort"`
	FrameCount     int      `json:"frameCount"`
	ByteCount      int64    `json:"byteCount"`
	StartEpoch     float64  `json:"startEpoch"`
	EndEpoch       float64  `json:"endEpoch"`
	Duration       string   `json:"duration"`
	Protocols      []string `json:"protocols"`
}

// ConversationSummary is STABLE.
// ConversationSummary describes one directional 5-tuple aggregate.
type ConversationSummary struct {
	Protocol   string   `json:"protocol"`
	SrcAddr    string   `json:"srcAddr"`
	SrcPort    int      `json:"srcPort"`
	DstAddr    string   `json:"dstAddr"`
	DstPort    int      `json:"dstPort"`
	FrameCount int      `json:"frameCount"`
	ByteCount  int64    `json:"byteCount"`
	StartEpoch float64  `json:"startEpoch"`
	EndEpoch   float64  `json:"endEpoch"`
	Duration   string   `json:"duration"`
	Protocols  []string `json:"protocols"`
}

// TimelineBucket is STABLE.
// TimelineBucket summarizes traffic in one wall-clock interval.
type TimelineBucket struct {
	StartEpoch int64          `json:"startEpoch"`
	EndEpoch   int64          `json:"endEpoch"`
	FrameCount int            `json:"frameCount"`
	ByteCount  int64          `json:"byteCount"`
	Protocols  map[string]int `json:"protocols"`
}

// FileObject is STABLE.
// FileObject describes file-like data observed in protocol dissections without
// writing the object to disk.
type FileObject struct {
	FrameNumber int    `json:"frameNumber"`
	Protocol    string `json:"protocol"`
	Filename    string `json:"filename,omitempty"`
	ContentType string `json:"contentType,omitempty"`
	Size        int64  `json:"size"`
	SrcAddr     string `json:"srcAddr,omitempty"`
	DstAddr     string `json:"dstAddr,omitempty"`
}

// Streams walks a capture and returns TCP/UDP stream aggregates with real
// Wireshark stream IDs (tcp.stream / udp.stream).
func Streams(path string, opts ...Option) ([]StreamSummary, error) {
	return StreamsContext(context.Background(), path, opts...)
}

// StreamsContext returns TCP/UDP stream aggregates using the provided context
// for session acquisition.
func StreamsContext(ctx context.Context, path string, opts ...Option) ([]StreamSummary, error) {
	s, err := OpenSessionContext(ctx, path, opts...)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return s.Streams(Query{Filter: extractFilter(opts)})
}

func fillStreamIDs(s *Session, q Query, streams []StreamSummary) {
	fields := []string{"ip.src", "ip.dst",
		"tcp.srcport", "tcp.dstport", "tcp.stream",
		"udp.srcport", "udp.dstport", "udp.stream"}

	rows, err := s.FieldsRows(q, fields)
	if err != nil {
		return
	}

	tcpHashToStream := map[uint32]int{}
	udpHashToStream := map[uint32]int{}

	for _, row := range rows {
		tcpSID := row["tcp.stream"]
		if tcpSID != "" {
			srcPort, _ := strconv.Atoi(row["tcp.srcport"])
			dstPort, _ := strconv.Atoi(row["tcp.dstport"])
			a1, a2 := sortPair(row["ip.src"], uint32(srcPort), row["ip.dst"], uint32(dstPort))
			h := streamHash(a1.Addr, a1.Port, a2.Addr, a2.Port)
			if _, ok := tcpHashToStream[h]; !ok {
				if sid, e := strconv.Atoi(tcpSID); e == nil {
					tcpHashToStream[h] = sid
				}
			}
		}

		udpSID := row["udp.stream"]
		if udpSID != "" {
			srcPort, _ := strconv.Atoi(row["udp.srcport"])
			dstPort, _ := strconv.Atoi(row["udp.dstport"])
			a1, a2 := sortPair(row["ip.src"], uint32(srcPort), row["ip.dst"], uint32(dstPort))
			h := streamHash(a1.Addr, a1.Port, a2.Addr, a2.Port)
			if _, ok := udpHashToStream[h]; !ok {
				if sid, e := strconv.Atoi(udpSID); e == nil {
					udpHashToStream[h] = sid
				}
			}
		}
	}

	for i := range streams {
		st := &streams[i]
		switch st.Protocol {
		case "tcp":
			if sid, ok := tcpHashToStream[uint32(st.ConversationID)]; ok {
				st.StreamID = sid
			}
		case "udp":
			if sid, ok := udpHashToStream[uint32(st.ConversationID)]; ok {
				st.StreamID = sid
			}
		}
	}
}

func tapConvsToStreams(convs []TapConversation, proto string) []StreamSummary {
	out := make([]StreamSummary, 0, len(convs))
	seen := make(map[uint32]bool, len(convs))

	for _, c := range convs {
		a1, a2 := sortPair(c.Addr1, c.Port1, c.Addr2, c.Port2)
		id := streamHash(a1.Addr, a1.Port, a2.Addr, a2.Port)
		if seen[id] {
			continue
		}
		seen[id] = true

		out = append(out, StreamSummary{
			Protocol:       proto,
			ConversationID: int(id),
			StreamID:       -1,
			SrcAddr:        a1.Addr,
			SrcPort:        int(a1.Port),
			DstAddr:        a2.Addr,
			DstPort:        int(a2.Port),
			FrameCount:     int(c.TotalPackets),
			ByteCount:      int64(c.TotalBytes),
			StartEpoch:     c.StartTime,
			EndEpoch:       c.StartTime + c.Duration,
			Duration:       formatDuration(c.Duration),
			Protocols:      []string{proto},
		})
	}
	return out
}

type addrPair struct {
	Addr string
	Port uint32
}

func sortPair(addr1 string, port1 uint32, addr2 string, port2 uint32) (addrPair, addrPair) {
	if addr1 < addr2 || (addr1 == addr2 && port1 < port2) {
		return addrPair{addr1, port1}, addrPair{addr2, port2}
	}
	return addrPair{addr2, port2}, addrPair{addr1, port1}
}

func streamHash(a1 string, p1 uint32, a2 string, p2 uint32) uint32 {
	h := fnv.New32a()
	h.Write([]byte(a1))
	h.Write([]byte{0})
	h.Write([]byte(fmt.Sprintf("%d", p1)))
	h.Write([]byte{0})
	h.Write([]byte(a2))
	h.Write([]byte{0})
	h.Write([]byte(fmt.Sprintf("%d", p2)))
	return h.Sum32()
}

func formatDuration(seconds float64) string {
	d := time.Duration(seconds * float64(time.Second))
	return d.String()
}

// Conversations walks a capture and returns directional 5-tuple aggregates.
func Conversations(path string, opts ...Option) ([]ConversationSummary, error) {
	return ConversationsContext(context.Background(), path, opts...)
}

// ConversationsContext walks a capture and returns directional 5-tuple
// aggregates using the provided context for session acquisition.
func ConversationsContext(ctx context.Context, path string, opts ...Option) ([]ConversationSummary, error) {
	s, err := OpenSessionContext(ctx, path, opts...)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return s.Conversations(Query{Filter: extractFilter(opts)})
}

// Timeline walks a capture and groups traffic into one-minute buckets.
func Timeline(path string, opts ...Option) ([]TimelineBucket, error) {
	return TimelineContext(context.Background(), path, opts...)
}

// TimelineContext groups traffic into one-minute buckets using the provided
// context for session acquisition.
func TimelineContext(ctx context.Context, path string, opts ...Option) ([]TimelineBucket, error) {
	return TimelineByContext(ctx, path, time.Minute, opts...)
}

// TimelineBy walks a capture and groups traffic into caller-selected buckets
// using the C-level timeline fast path for performance.
func TimelineBy(path string, bucket time.Duration, opts ...Option) ([]TimelineBucket, error) {
	return TimelineByContext(context.Background(), path, bucket, opts...)
}

// TimelineByContext walks a capture and groups traffic into caller-selected
// buckets using the provided context for session acquisition.
func TimelineByContext(ctx context.Context, path string, bucket time.Duration, opts ...Option) ([]TimelineBucket, error) {
	s, err := OpenSessionContext(ctx, path, opts...)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return s.TimelineBy(Query{Filter: extractFilter(opts)}, bucket)
}

// Files walks a capture and returns file-like metadata surfaced by dissectors.
//
// Files tries a field-only fast path first, extracting http.file_data,
// http.content_type, and frame metadata via FieldsRows. If the field-only
// extraction fails (e.g. because http.file_data is not exposed by the field
// extractor), it falls back to a full WalkFrames + ParseFrameData scan.
func Files(path string, opts ...Option) ([]FileObject, error) {
	return FilesContext(context.Background(), path, opts...)
}

// FilesContext walks a capture and returns file-like metadata surfaced by
// dissectors using the provided context for session acquisition.
func FilesContext(ctx context.Context, path string, opts ...Option) ([]FileObject, error) {
	s, sessErr := OpenSessionContext(ctx, path, opts...)
	if sessErr != nil {
		return nil, sessErr
	}
	defer s.Close()

	q := Query{Filter: extractFilter(opts)}

	fields := []string{"frame.number", "http.file_data", "http.content_type", "ip.src", "ip.dst"}
	rows, fieldErr := s.FieldsRows(q, fields)
	if fieldErr == nil {
		var out []FileObject
		for _, row := range rows {
			fileData := row["http.file_data"]
			if fileData == "" {
				continue
			}
			fo := FileObject{
				Protocol:    "http",
				ContentType: row["http.content_type"],
				Size:        int64(len(fileData) / 2),
				SrcAddr:     row["ip.src"],
				DstAddr:     row["ip.dst"],
			}
			if n, perr := strconv.Atoi(row["frame.number"]); perr == nil {
				fo.FrameNumber = n
			}
			out = append(out, fo)
		}
		return out, nil
	}

	// Reuse the already-open Session instead of calling WalkFramesContext,
	// which would try to OpenSessionContext again and deadlock on sessionGate
	// (the single in-process Session token is held by s until defer s.Close()).
	var out []FileObject
	walkErr := s.WalkFrames(q, func(f *FrameData) error {
		out = append(out, filesFromFrame(f)...)
		return nil
	})
	return out, walkErr
}

type trafficAccumulator struct {
	streamMap map[string]*StreamSummary
	convMap   map[string]*ConversationSummary
}

func newTrafficAccumulator() *trafficAccumulator {
	return &trafficAccumulator{streamMap: map[string]*StreamSummary{}, convMap: map[string]*ConversationSummary{}}
}

func (a *trafficAccumulator) addFrame(f *FrameData) {
	if f == nil || f.BaseLayers.Frame == nil || f.BaseLayers.IP == nil {
		return
	}
	fr := f.BaseLayers.Frame
	ip := f.BaseLayers.IP
	proto, streamID, srcPort, dstPort, ok := transportTuple(f)
	if !ok {
		return
	}
	a.accumulate(proto, streamID, srcPort, dstPort, ip.Src, ip.Dst, fr.TimeEpoch, int64(fr.Len), fr.Protocols)
}

func (a *trafficAccumulator) addRow(row map[string]string) {
	ipSrc := row["ip.src"]
	ipDst := row["ip.dst"]
	if ipSrc == "" || ipDst == "" {
		return
	}

	byteCount, _ := strconv.ParseInt(row["frame.len"], 10, 64)
	timeEpoch, _ := strconv.ParseFloat(row["frame.time_epoch"], 64)

	tcpSrcPort, _ := strconv.Atoi(row["tcp.srcport"])
	tcpDstPort, _ := strconv.Atoi(row["tcp.dstport"])
	tcpStream, _ := strconv.Atoi(row["tcp.stream"])
	udpSrcPort, _ := strconv.Atoi(row["udp.srcport"])
	udpDstPort, _ := strconv.Atoi(row["udp.dstport"])
	udpStream, _ := strconv.Atoi(row["udp.stream"])

	var proto string
	var streamID, srcPort, dstPort int
	if tcpSrcPort > 0 {
		proto = "tcp"
		streamID = tcpStream
		srcPort = tcpSrcPort
		dstPort = tcpDstPort
	} else if udpSrcPort > 0 {
		proto = "udp"
		streamID = udpStream
		srcPort = udpSrcPort
		dstPort = udpDstPort
	} else {
		return
	}

	a.accumulate(proto, streamID, srcPort, dstPort, ipSrc, ipDst, timeEpoch, byteCount, row["frame.protocols"])
}

func (a *trafficAccumulator) accumulate(proto string, streamID, srcPort, dstPort int,
	srcAddr, dstAddr string, timeEpoch float64, byteCount int64, protocols string) {

	protos := protocolList(protocols)

	sk := proto + ":" + strconv.Itoa(streamID)
	s := a.streamMap[sk]
	if s == nil {
		a1, a2 := sortPair(srcAddr, uint32(srcPort), dstAddr, uint32(dstPort))
		convID := int(streamHash(a1.Addr, a1.Port, a2.Addr, a2.Port))
		s = &StreamSummary{Protocol: proto, ConversationID: convID, StreamID: streamID, SrcAddr: srcAddr, SrcPort: srcPort, DstAddr: dstAddr, DstPort: dstPort, Protocols: protos}
		a.streamMap[sk] = s
	}
	updateStreamSummary(s, timeEpoch, byteCount, protos)

	ck := proto + ":" + srcAddr + ":" + strconv.Itoa(srcPort) + ">" + dstAddr + ":" + strconv.Itoa(dstPort)
	c := a.convMap[ck]
	if c == nil {
		c = &ConversationSummary{Protocol: proto, SrcAddr: srcAddr, SrcPort: srcPort, DstAddr: dstAddr, DstPort: dstPort, Protocols: protos}
		a.convMap[ck] = c
	}
	updateConversationSummary(c, timeEpoch, byteCount, protos)
}

func (a *trafficAccumulator) streams() []StreamSummary {
	out := make([]StreamSummary, 0, len(a.streamMap))
	for _, s := range a.streamMap {
		finalizeStream(s)
		out = append(out, *s)
	}
	slices.SortFunc(out, func(a, b StreamSummary) int {
		if a.Protocol != b.Protocol {
			return strings.Compare(a.Protocol, b.Protocol)
		}
		return a.StreamID - b.StreamID
	})
	return out
}

func (a *trafficAccumulator) conversations() []ConversationSummary {
	out := make([]ConversationSummary, 0, len(a.convMap))
	for _, c := range a.convMap {
		finalizeConversation(c)
		out = append(out, *c)
	}
	slices.SortFunc(out, func(a, b ConversationSummary) int {
		if a.ByteCount != b.ByteCount {
			return int(b.ByteCount - a.ByteCount)
		}
		return b.FrameCount - a.FrameCount
	})
	return out
}

func transportTuple(f *FrameData) (proto string, streamID, srcPort, dstPort int, ok bool) {
	if f.BaseLayers.TCP != nil {
		return "tcp", f.BaseLayers.TCP.Stream, f.BaseLayers.TCP.SrcPort, f.BaseLayers.TCP.DstPort, true
	}
	if f.BaseLayers.UDP != nil {
		return "udp", f.BaseLayers.UDP.Stream, f.BaseLayers.UDP.SrcPort, f.BaseLayers.UDP.DstPort, true
	}
	return "", 0, 0, 0, false
}

func updateStreamSummary(s *StreamSummary, ts float64, bytes int64, protos []string) {
	s.FrameCount++
	s.ByteCount += bytes
	if ts > 0 && (s.StartEpoch == 0 || ts < s.StartEpoch) {
		s.StartEpoch = ts
	}
	if ts > s.EndEpoch {
		s.EndEpoch = ts
	}
	s.Protocols = mergeProtocols(s.Protocols, protos)
}

func updateConversationSummary(c *ConversationSummary, ts float64, bytes int64, protos []string) {
	c.FrameCount++
	c.ByteCount += bytes
	if ts > 0 && (c.StartEpoch == 0 || ts < c.StartEpoch) {
		c.StartEpoch = ts
	}
	if ts > c.EndEpoch {
		c.EndEpoch = ts
	}
	c.Protocols = mergeProtocols(c.Protocols, protos)
}

func finalizeStream(s *StreamSummary) {
	if s.EndEpoch > s.StartEpoch {
		s.Duration = time.Duration((s.EndEpoch - s.StartEpoch) * float64(time.Second)).String()
	}
}

func finalizeConversation(c *ConversationSummary) {
	if c.EndEpoch > c.StartEpoch {
		c.Duration = time.Duration((c.EndEpoch - c.StartEpoch) * float64(time.Second)).String()
	}
}

func protocolList(protocols string) []string {
	parts := strings.Split(protocols, ":")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func mergeProtocols(existing, added []string) []string {
	seen := make(map[string]bool, len(existing)+len(added))
	out := make([]string, 0, len(existing)+len(added))
	for _, p := range append(existing, added...) {
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

func filesFromFrame(f *FrameData) []FileObject {
	if f == nil || f.BaseLayers.Frame == nil {
		return nil
	}
	var out []FileObject
	if f.BaseLayers.HTTP != nil {
		for _, h := range f.BaseLayers.HTTP {
			if h == nil || h.FileData == "" {
				continue
			}
			fo := FileObject{FrameNumber: f.BaseLayers.Frame.Number, Protocol: "http", ContentType: h.ContentType, Size: int64(len(h.FileData) / 2)}
			if f.BaseLayers.IP != nil {
				fo.SrcAddr, fo.DstAddr = f.BaseLayers.IP.Src, f.BaseLayers.IP.Dst
			}
			out = append(out, fo)
		}
	}
	return out
}
