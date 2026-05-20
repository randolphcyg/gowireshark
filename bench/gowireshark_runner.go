package bench

import (
	"bytes"
	"fmt"
	"io"
	"sync"

	"github.com/randolphcyg/gowireshark"
)

type GowiresharkRunner struct {
	pcap string
}

func NewGowiresharkRunner(pcap string) *GowiresharkRunner {
	return &GowiresharkRunner{pcap: pcap}
}

func (r *GowiresharkRunner) FrameLookupCold(frameNum int) (records int, bytesOut int64, err error) {
	s, openErr := gowireshark.OpenSession(r.pcap)
	if openErr != nil {
		return 0, 0, openErr
	}
	defer s.Close()

	f, fErr := s.FrameByIndex(frameNum)
	if fErr != nil {
		return 0, 0, fErr
	}
	buf := &bytes.Buffer{}
	err = marshalFrameData(buf, f)
	if err != nil {
		return 0, 0, err
	}
	return 1, int64(buf.Len()), nil
}

func (r *GowiresharkRunner) ExpertInfoCold() (records int, bytesOut int64, err error) {
	infos, err := gowireshark.ExpertInfos(r.pcap)
	if err != nil {
		return 0, 0, err
	}
	buf := &bytes.Buffer{}
	for _, info := range infos {
		buf.WriteString(info.Message)
		buf.WriteByte('\n')
	}
	return len(infos), int64(buf.Len()), nil
}

func (r *GowiresharkRunner) FollowStreamCold(streamFilter string) (records int, bytesOut int64, err error) {
	result, err := gowireshark.FollowStream(r.pcap, streamFilter, "tcp")
	if err != nil {
		return 0, 0, err
	}
	payloadBytes := 0
	for _, p := range result.Payloads {
		payloadBytes += len(p.Bytes)
	}
	return result.PacketCount, int64(payloadBytes), nil
}

func (r *GowiresharkRunner) StreamListCold() (records int, bytesOut int64, err error) {
	streams, err := gowireshark.Streams(r.pcap)
	if err != nil {
		return 0, 0, err
	}
	buf := &bytes.Buffer{}
	for _, s := range streams {
		writeStreamSummary(buf, &s)
	}
	return len(streams), int64(buf.Len()), nil
}

func (r *GowiresharkRunner) StreamListTCPCold() (records int, bytesOut int64, err error) {
	return r.streamListColdByProto("tcp")
}

func (r *GowiresharkRunner) StreamListUDPCold() (records int, bytesOut int64, err error) {
	return r.streamListColdByProto("udp")
}

func (r *GowiresharkRunner) streamListColdByProto(proto string) (records int, bytesOut int64, err error) {
	s, openErr := gowireshark.OpenSession(r.pcap)
	if openErr != nil {
		return 0, 0, openErr
	}
	defer s.Close()

	tcpConvs, err := s.TapConversations(proto, gowireshark.Query{})
	if err != nil {
		return 0, 0, err
	}

	buf := &bytes.Buffer{}
	for _, c := range tcpConvs {
		line := fmt.Sprintf("%s: %s:%d -> %s:%d\n", proto, c.Addr1, c.Port1, c.Addr2, c.Port2)
		buf.Write([]byte(line))
	}
	return len(tcpConvs), int64(buf.Len()), nil
}

func (r *GowiresharkRunner) FollowStreamColdReal(streamFilter string) (records int, bytesOut int64, err error) {
	result, err := gowireshark.FollowStream(r.pcap, streamFilter, "tcp")
	if err != nil {
		return 0, 0, err
	}
	payloadBytes := 0
	for _, p := range result.Payloads {
		payloadBytes += len(p.Bytes)
	}
	if result.PacketCount == 0 {
		return 0, 0, fmt.Errorf("follow_stream_real: zero packet count for filter %q", streamFilter)
	}
	return result.PacketCount, int64(payloadBytes), nil
}

func (r *GowiresharkRunner) PcapSliceCold(maxFrames int) (records int, bytesOut int64, err error) {
	buf := &bytes.Buffer{}
	count, err := gowireshark.WritePcapSlice(r.pcap, buf, gowireshark.FrameSelector{
		Filter: "frame.number <= 100",
	})
	if err != nil {
		return 0, 0, err
	}
	return count, int64(buf.Len()), nil
}

type WarmSession struct {
	mu   sync.Mutex
	pcap string
	sess *gowireshark.Session
}

func NewWarmSession(pcap string) *WarmSession {
	return &WarmSession{pcap: pcap}
}

func (ws *WarmSession) Setup() error {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	if ws.sess != nil {
		return nil
	}
	s, err := gowireshark.OpenSession(ws.pcap)
	if err != nil {
		return err
	}
	ws.sess = s
	return nil
}

func (ws *WarmSession) Teardown() {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	if ws.sess != nil {
		ws.sess.Close()
		ws.sess = nil
	}
}

func (ws *WarmSession) FrameLookup(frameNum int) (records int, bytesOut int64, err error) {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	f, fErr := ws.sess.FrameByIndex(frameNum)
	if fErr != nil {
		return 0, 0, fErr
	}
	buf := &bytes.Buffer{}
	err = marshalFrameData(buf, f)
	if err != nil {
		return 0, 0, err
	}
	return 1, int64(buf.Len()), nil
}

func (ws *WarmSession) ExpertInfo() (records int, bytesOut int64, err error) {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	infos, err := ws.sess.ExpertInfos(gowireshark.Query{})
	if err != nil {
		return 0, 0, err
	}
	buf := &bytes.Buffer{}
	for _, info := range infos {
		buf.WriteString(info.Message)
		buf.WriteByte('\n')
	}
	return len(infos), int64(buf.Len()), nil
}

func (ws *WarmSession) FollowStream(streamFilter string) (records int, bytesOut int64, err error) {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	result, err := ws.sess.FollowStream(gowireshark.Query{Filter: streamFilter}, "tcp")
	if err != nil {
		return 0, 0, err
	}
	payloadBytes := 0
	for _, p := range result.Payloads {
		payloadBytes += len(p.Bytes)
	}
	return result.PacketCount, int64(payloadBytes), nil
}

func (ws *WarmSession) StreamList() (records int, bytesOut int64, err error) {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	streams, err := ws.sess.Streams(gowireshark.Query{})
	if err != nil {
		return 0, 0, err
	}
	buf := &bytes.Buffer{}
	for _, s := range streams {
		writeStreamSummary(buf, &s)
	}
	return len(streams), int64(buf.Len()), nil
}

func (ws *WarmSession) StreamListTCP() (records int, bytesOut int64, err error) {
	return ws.streamListByProto("tcp")
}

func (ws *WarmSession) StreamListUDP() (records int, bytesOut int64, err error) {
	return ws.streamListByProto("udp")
}

func (ws *WarmSession) streamListByProto(proto string) (records int, bytesOut int64, err error) {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	convs, err := ws.sess.TapConversations(proto, gowireshark.Query{})
	if err != nil {
		return 0, 0, err
	}
	buf := &bytes.Buffer{}
	for _, c := range convs {
		line := fmt.Sprintf("%s: %s:%d -> %s:%d\n", proto, c.Addr1, c.Port1, c.Addr2, c.Port2)
		buf.Write([]byte(line))
	}
	return len(convs), int64(buf.Len()), nil
}

func (r *GowiresharkRunner) FrameCount() int {
	count := r.frameCountFromSession()
	if count < 0 {
		return 0
	}
	return count
}

func (r *GowiresharkRunner) HasTCP() bool {
	return r.hasTCPFromSession()
}

func (r *GowiresharkRunner) FirstTCPStream() int {
	return r.firstTCPStreamFromSession()
}

func (ws *WarmSession) PcapSlice(maxFrames int) (records int, bytesOut int64, err error) {
	ws.mu.Lock()

	var indices []int
	err = ws.sess.WalkFrames(gowireshark.Query{Filter: "frame.number <= 100"}, func(f *gowireshark.FrameData) error {
		if f != nil && f.BaseLayers.Frame != nil {
			indices = append(indices, f.BaseLayers.Frame.Number)
		}
		return nil
	})
	ws.mu.Unlock()

	if err != nil {
		return 0, 0, err
	}
	if len(indices) == 0 {
		return 0, 0, gowireshark.ErrEmptySelection
	}

	buf := &bytes.Buffer{}
	count, err := gowireshark.WritePcapSlice(ws.pcap, buf, gowireshark.FrameSelector{
		Indices: indices,
	})
	if err != nil {
		return 0, 0, err
	}
	return count, int64(buf.Len()), nil
}

func (r *GowiresharkRunner) frameCountFromSession() int {
	s, err := r.openSession()
	if err != nil {
		return 0
	}
	defer s.Close()
	return s.TotalFrames()
}

func (r *GowiresharkRunner) hasTCPFromSession() bool {
	s, err := r.openSession()
	if err != nil {
		return false
	}
	defer s.Close()
	streams, err := s.Streams(gowireshark.Query{})
	if err != nil {
		return false
	}
	for _, st := range streams {
		if st.Protocol == "tcp" {
			return true
		}
	}
	return false
}

func (r *GowiresharkRunner) firstTCPStreamFromSession() int {
	s, err := r.openSession()
	if err != nil {
		return -1
	}
	defer s.Close()
	streams, err := s.Streams(gowireshark.Query{})
	if err != nil {
		return -1
	}
	for _, st := range streams {
		if st.Protocol == "tcp" && st.StreamID >= 0 {
			return st.StreamID
		}
	}
	return -1
}

func (r *GowiresharkRunner) openSession() (*gowireshark.Session, error) {
	return gowireshark.OpenSession(r.pcap)
}

func marshalFrameData(w io.Writer, f *gowireshark.FrameData) error {
	if f == nil || f.BaseLayers.Frame == nil {
		_, err := w.Write([]byte("{}"))
		return err
	}
	data := []byte("{\"num\":" + itoa(f.BaseLayers.Frame.Number) + "}")
	_, err := w.Write(data)
	return err
}

func writeStreamSummary(w io.Writer, s *gowireshark.StreamSummary) {
	line := s.Protocol + ":" + itoa(s.ConversationID) + " " + s.SrcAddr + ":" + itoa(s.SrcPort) + " -> " + s.DstAddr + ":" + itoa(s.DstPort) + "\n"
	w.Write([]byte(line))
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}