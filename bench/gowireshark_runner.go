package bench

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/randolphcyg/gowireshark"
)

type GowiresharkRunner struct {
	pcap string
}

func NewGowiresharkRunner(pcap string) *GowiresharkRunner {
	return &GowiresharkRunner{pcap: pcap}
}

func (r *GowiresharkRunner) FrameLookupCold(frameNum int) (records int, bytesOut int64, err error) {
	s, openErr := gowireshark.OpenSessionContext(context.Background(), r.pcap)
	if openErr != nil {
		return 0, 0, openErr
	}
	defer s.Close()

	f, fErr := s.Frame(frameNum)
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
	s, openErr := gowireshark.OpenSessionContext(context.Background(), r.pcap)
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

func (r *GowiresharkRunner) FieldsCold(fields []string) (records int, bytesOut int64, err error) {
	rows, err := gowireshark.FieldsRows(r.pcap, fields)
	if err != nil {
		return 0, 0, err
	}
	buf := &bytes.Buffer{}
	for _, row := range rows {
		for _, f := range fields {
			buf.WriteString(row[f])
			buf.WriteByte('\t')
		}
		buf.WriteByte('\n')
	}
	return len(rows), int64(buf.Len()), nil
}

func (r *GowiresharkRunner) FieldsRowsOccurrenceCold(fields []string, occurrence gowireshark.FieldOccurrence) (records int, bytesOut int64, err error) {
	rows, err := gowireshark.FieldsRows(r.pcap, fields, gowireshark.WithFieldOccurrence(occurrence))
	if err != nil {
		return 0, 0, err
	}
	buf := &bytes.Buffer{}
	for _, row := range rows {
		for _, f := range fields {
			buf.WriteString(row[f])
			buf.WriteByte('\t')
		}
		buf.WriteByte('\n')
	}
	return len(rows), int64(buf.Len()), nil
}

func (r *GowiresharkRunner) FieldsRowsValuesCold(fields []string) (records int, bytesOut int64, err error) {
	rows, err := gowireshark.FieldsRowsValues(r.pcap, fields)
	if err != nil {
		return 0, 0, err
	}
	buf := &bytes.Buffer{}
	for _, row := range rows {
		buf.WriteString(strconv.Itoa(row.FrameNumber))
		for _, f := range fields {
			buf.WriteByte('\t')
			buf.WriteString(strings.Join(row.Values[f], ","))
		}
		buf.WriteByte('\n')
	}
	return len(rows), int64(buf.Len()), nil
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

func (r *GowiresharkRunner) FrameNumbersCold(filter string) (records int, bytesOut int64, err error) {
	var opts []gowireshark.Option
	if filter != "" {
		opts = append(opts, gowireshark.WithDisplayFilter(filter))
	}
	nums, err := gowireshark.FrameNumbers(r.pcap, opts...)
	if err != nil {
		return 0, 0, err
	}
	buf := &bytes.Buffer{}
	for _, n := range nums {
		buf.WriteString(itoa(n))
		buf.WriteByte('\n')
	}
	return len(nums), int64(buf.Len()), nil
}

func (r *GowiresharkRunner) TimelineCold() (records int, bytesOut int64, err error) {
	buckets, err := gowireshark.Timeline(r.pcap)
	if err != nil {
		return 0, 0, err
	}
	buf := &bytes.Buffer{}
	for _, b := range buckets {
		fmt.Fprintf(buf, "%d\t%d\t%d\n", b.StartEpoch, b.FrameCount, b.ByteCount)
	}
	return len(buckets), int64(buf.Len()), nil
}

func (r *GowiresharkRunner) IOStatsCold(intervalSecs float64) (records int, bytesOut int64, err error) {
	buckets, err := gowireshark.IOStats(r.pcap, time.Duration(intervalSecs*float64(time.Second)))
	if err != nil {
		return 0, 0, err
	}
	buf := &bytes.Buffer{}
	for _, b := range buckets {
		fmt.Fprintf(buf, "%.3f\t%d\t%d\n", b.Time, b.Packets, b.Bytes)
	}
	return len(buckets), int64(buf.Len()), nil
}

func (r *GowiresharkRunner) ProtocolHierarchyCold() (records int, bytesOut int64, err error) {
	entries, err := gowireshark.ProtocolHierarchy(r.pcap)
	if err != nil {
		return 0, 0, err
	}
	buf := &bytes.Buffer{}
	for _, e := range entries {
		fmt.Fprintf(buf, "%s\t%d\t%d\n", e.Protocol, e.Packets, e.Bytes)
	}
	return len(entries), int64(buf.Len()), nil
}

func (r *GowiresharkRunner) ServiceResponseTimesCold(protocol string) (records int, bytesOut int64, err error) {
	entries, err := gowireshark.ServiceResponseTimes(r.pcap, protocol)
	if err != nil {
		return 0, 0, err
	}
	buf := &bytes.Buffer{}
	for _, e := range entries {
		fmt.Fprintf(buf, "%s\t%d\t%.3f\t%.3f\n", e.Procedure, e.Calls, e.Min, e.Avg)
	}
	return len(entries), int64(buf.Len()), nil
}

func (r *GowiresharkRunner) WriteDissectionTextCold() (records int, bytesOut int64, err error) {
	buf := &bytes.Buffer{}
	count, err := gowireshark.WriteDissectionContext(context.Background(),
		r.pcap, buf, gowireshark.OutputText)
	_ = count
	if err != nil {
		return 0, 0, err
	}
	return countLines(buf.String()), int64(buf.Len()), nil
}

func (r *GowiresharkRunner) WriteDissectionPDMLCold() (records int, bytesOut int64, err error) {
	buf := &bytes.Buffer{}
	count, err := gowireshark.WriteDissectionContext(context.Background(),
		r.pcap, buf, gowireshark.OutputPDML)
	_ = count
	if err != nil {
		return 0, 0, err
	}
	return countLines(buf.String()), int64(buf.Len()), nil
}

func (r *GowiresharkRunner) TapConversationsCold(convType string) (records int, bytesOut int64, err error) {
	convs, err := gowireshark.TapConversations(r.pcap, convType)
	if err != nil {
		return 0, 0, err
	}
	buf := &bytes.Buffer{}
	for _, c := range convs {
		fmt.Fprintf(buf, "%s\t%s:%d->%s:%d\t%d\t%d\n", convType, c.Addr1, c.Port1, c.Addr2, c.Port2, c.TotalPackets, c.TotalBytes)
	}
	return len(convs), int64(buf.Len()), nil
}

func (r *GowiresharkRunner) TapEndpointsCold(endpointType string) (records int, bytesOut int64, err error) {
	endpoints, err := gowireshark.TapEndpoints(r.pcap, endpointType)
	if err != nil {
		return 0, 0, err
	}
	buf := &bytes.Buffer{}
	for _, ep := range endpoints {
		fmt.Fprintf(buf, "%s\t%s:%d\t%d\n", endpointType, ep.Address, ep.Port, ep.Packets)
	}
	return len(endpoints), int64(buf.Len()), nil
}

func (r *GowiresharkRunner) IterFramesCold() (records int, bytesOut int64, err error) {
	s, openErr := gowireshark.OpenSessionContext(context.Background(), r.pcap)
	if openErr != nil {
		return 0, 0, openErr
	}
	defer s.Close()

	iter, iterErr := s.IterFrames(gowireshark.Query{})
	if iterErr != nil {
		return 0, 0, iterErr
	}
	count := 0
	for iter.Next() {
		_ = iter.Frame()
		count++
	}
	if cerr := iter.Close(); cerr != nil {
		return count, 0, cerr
	}
	return count, 0, nil
}

func (r *GowiresharkRunner) WriteFieldsRowsCold(fields []string) (records int, bytesOut int64, err error) {
	s, openErr := gowireshark.OpenSessionContext(context.Background(), r.pcap)
	if openErr != nil {
		return 0, 0, openErr
	}
	defer s.Close()

	buf := &bytes.Buffer{}
	count, writeErr := s.WriteFieldsRows(gowireshark.Query{}, fields, buf)
	if writeErr != nil {
		return 0, 0, writeErr
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
	s, err := gowireshark.OpenSessionContext(context.Background(), ws.pcap)
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
	f, fErr := ws.sess.Frame(frameNum)
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
	defer ws.mu.Unlock()

	buf := &bytes.Buffer{}
	count, err := ws.sess.WritePcapSlice(buf, gowireshark.FrameSelector{
		Filter: "frame.number <= 100",
	})
	if err != nil {
		return 0, 0, err
	}
	return count, int64(buf.Len()), nil
}

func (ws *WarmSession) Fields(fields []string) (records int, bytesOut int64, err error) {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	rows, err := ws.sess.FieldsRows(gowireshark.Query{}, fields)
	if err != nil {
		return 0, 0, err
	}
	buf := &bytes.Buffer{}
	for _, row := range rows {
		for _, f := range fields {
			buf.WriteString(row[f])
			buf.WriteByte('\t')
		}
		buf.WriteByte('\n')
	}
	return len(rows), int64(buf.Len()), nil
}

func (ws *WarmSession) FieldsRowsOccurrence(fields []string, occurrence gowireshark.FieldOccurrence) (records int, bytesOut int64, err error) {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	rows, err := ws.sess.FieldsRows(gowireshark.Query{}, fields, gowireshark.WithFieldOccurrence(occurrence))
	if err != nil {
		return 0, 0, err
	}
	buf := &bytes.Buffer{}
	for _, row := range rows {
		for _, f := range fields {
			buf.WriteString(row[f])
			buf.WriteByte('\t')
		}
		buf.WriteByte('\n')
	}
	return len(rows), int64(buf.Len()), nil
}

func (ws *WarmSession) FieldsRowsValues(fields []string) (records int, bytesOut int64, err error) {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	rows, err := ws.sess.FieldsRowsValues(gowireshark.Query{}, fields)
	if err != nil {
		return 0, 0, err
	}
	buf := &bytes.Buffer{}
	for _, row := range rows {
		buf.WriteString(strconv.Itoa(row.FrameNumber))
		for _, f := range fields {
			buf.WriteByte('\t')
			buf.WriteString(strings.Join(row.Values[f], ","))
		}
		buf.WriteByte('\n')
	}
	return len(rows), int64(buf.Len()), nil
}

func (ws *WarmSession) FrameNumbers(filter string) (records int, bytesOut int64, err error) {
	ws.mu.Lock()
	nums, err := ws.sess.FrameNumbers(gowireshark.Query{Filter: filter})
	ws.mu.Unlock()
	if err != nil {
		return 0, 0, err
	}
	buf := &bytes.Buffer{}
	for _, n := range nums {
		buf.WriteString(itoa(n))
		buf.WriteByte('\n')
	}
	return len(nums), int64(buf.Len()), nil
}

func (ws *WarmSession) Timeline() (records int, bytesOut int64, err error) {
	ws.mu.Lock()
	buckets, err := ws.sess.TimelineBy(gowireshark.Query{}, time.Second)
	ws.mu.Unlock()
	if err != nil {
		return 0, 0, err
	}
	buf := &bytes.Buffer{}
	for _, b := range buckets {
		fmt.Fprintf(buf, "%d\t%d\t%d\n", b.StartEpoch, b.FrameCount, b.ByteCount)
	}
	return len(buckets), int64(buf.Len()), nil
}

func (ws *WarmSession) IOStats(intervalSecs float64) (records int, bytesOut int64, err error) {
	ws.mu.Lock()
	buckets, err := ws.sess.IOStats(gowireshark.Query{}, time.Duration(intervalSecs*float64(time.Second)))
	ws.mu.Unlock()
	if err != nil {
		return 0, 0, err
	}
	buf := &bytes.Buffer{}
	for _, b := range buckets {
		fmt.Fprintf(buf, "%.3f\t%d\t%d\n", b.Time, b.Packets, b.Bytes)
	}
	return len(buckets), int64(buf.Len()), nil
}

func (ws *WarmSession) ProtocolHierarchy() (records int, bytesOut int64, err error) {
	ws.mu.Lock()
	entries, err := ws.sess.ProtocolHierarchy(gowireshark.Query{})
	ws.mu.Unlock()
	if err != nil {
		return 0, 0, err
	}
	buf := &bytes.Buffer{}
	for _, e := range entries {
		fmt.Fprintf(buf, "%s\t%d\t%d\n", e.Protocol, e.Packets, e.Bytes)
	}
	return len(entries), int64(buf.Len()), nil
}

func (ws *WarmSession) ServiceResponseTimes(protocol string) (records int, bytesOut int64, err error) {
	ws.mu.Lock()
	entries, err := ws.sess.ServiceResponseTimes(protocol, gowireshark.Query{})
	ws.mu.Unlock()
	if err != nil {
		return 0, 0, err
	}
	buf := &bytes.Buffer{}
	for _, e := range entries {
		fmt.Fprintf(buf, "%s\t%d\t%.3f\t%.3f\n", e.Procedure, e.Calls, e.Min, e.Avg)
	}
	return len(entries), int64(buf.Len()), nil
}

func (ws *WarmSession) WriteDissectionText() (records int, bytesOut int64, err error) {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	buf := &bytes.Buffer{}
	count, err := ws.sess.WriteDissection(buf, gowireshark.OutputText, gowireshark.Query{})
	_ = count
	if err != nil {
		return 0, 0, err
	}
	return countLines(buf.String()), int64(buf.Len()), nil
}

func (ws *WarmSession) WriteDissectionPDML() (records int, bytesOut int64, err error) {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	buf := &bytes.Buffer{}
	count, err := ws.sess.WriteDissection(buf, gowireshark.OutputPDML, gowireshark.Query{})
	_ = count
	if err != nil {
		return 0, 0, err
	}
	return countLines(buf.String()), int64(buf.Len()), nil
}

func (ws *WarmSession) TapConversations(convType string) (records int, bytesOut int64, err error) {
	ws.mu.Lock()
	convs, err := ws.sess.TapConversations(convType, gowireshark.Query{})
	ws.mu.Unlock()
	if err != nil {
		return 0, 0, err
	}
	buf := &bytes.Buffer{}
	for _, c := range convs {
		fmt.Fprintf(buf, "%s\t%s:%d->%s:%d\t%d\t%d\n", convType, c.Addr1, c.Port1, c.Addr2, c.Port2, c.TotalPackets, c.TotalBytes)
	}
	return len(convs), int64(buf.Len()), nil
}

func (ws *WarmSession) TapEndpoints(endpointType string) (records int, bytesOut int64, err error) {
	ws.mu.Lock()
	endpoints, err := ws.sess.TapEndpoints(endpointType, gowireshark.Query{})
	ws.mu.Unlock()
	if err != nil {
		return 0, 0, err
	}
	buf := &bytes.Buffer{}
	for _, ep := range endpoints {
		fmt.Fprintf(buf, "%s\t%s:%d\t%d\n", endpointType, ep.Address, ep.Port, ep.Packets)
	}
	return len(endpoints), int64(buf.Len()), nil
}

func (ws *WarmSession) IterFrames() (records int, bytesOut int64, err error) {
	ws.mu.Lock()
	iter, iterErr := ws.sess.IterFrames(gowireshark.Query{})
	ws.mu.Unlock()
	if iterErr != nil {
		return 0, 0, iterErr
	}
	count := 0
	for iter.Next() {
		_ = iter.Frame()
		count++
	}
	if cerr := iter.Close(); cerr != nil {
		return count, 0, cerr
	}
	return count, 0, nil
}

func (ws *WarmSession) WriteFieldsRows(fields []string) (records int, bytesOut int64, err error) {
	ws.mu.Lock()
	buf := &bytes.Buffer{}
	count, err := ws.sess.WriteFieldsRows(gowireshark.Query{}, fields, buf)
	ws.mu.Unlock()
	if err != nil {
		return 0, 0, err
	}
	return count, int64(buf.Len()), nil
}

func (r *GowiresharkRunner) IterFrameJSONCold() (records int, bytesOut int64, err error) {
	s, openErr := gowireshark.OpenSessionContext(context.Background(), r.pcap)
	if openErr != nil {
		return 0, 0, openErr
	}
	defer s.Close()

	iter, iterErr := s.IterFrameJSON(gowireshark.Query{})
	if iterErr != nil {
		return 0, 0, iterErr
	}
	count := 0
	byteCount := 0
	for iter.Next() {
		byteCount += len(iter.JSON())
		count++
	}
	if cerr := iter.Close(); cerr != nil {
		return count, 0, cerr
	}
	return count, int64(byteCount), nil
}

func (ws *WarmSession) IterFrameJSON() (records int, bytesOut int64, err error) {
	iter, iterErr := ws.sess.IterFrameJSON(gowireshark.Query{})
	if iterErr != nil {
		return 0, 0, iterErr
	}
	count := 0
	byteCount := 0
	for iter.Next() {
		byteCount += len(iter.JSON())
		count++
	}
	if cerr := iter.Close(); cerr != nil {
		return count, 0, cerr
	}
	return count, int64(byteCount), nil
}

func (r *GowiresharkRunner) ConversationsCold() (records int, bytesOut int64, err error) {
	s, openErr := gowireshark.OpenSessionContext(context.Background(), r.pcap)
	if openErr != nil {
		return 0, 0, openErr
	}
	defer s.Close()

	convs, err := s.Conversations(gowireshark.Query{})
	if err != nil {
		return 0, 0, err
	}
	buf := &bytes.Buffer{}
	for _, c := range convs {
		fmt.Fprintf(buf, "%s\t%s:%d->%s:%d\t%d\t%d\n", c.Protocol, c.SrcAddr, c.SrcPort, c.DstAddr, c.DstPort, c.FrameCount, c.ByteCount)
	}
	return len(convs), int64(buf.Len()), nil
}

func (ws *WarmSession) Conversations() (records int, bytesOut int64, err error) {
	convs, err := ws.sess.Conversations(gowireshark.Query{})
	if err != nil {
		return 0, 0, err
	}
	buf := &bytes.Buffer{}
	for _, c := range convs {
		fmt.Fprintf(buf, "%s\t%s:%d->%s:%d\t%d\t%d\n", c.Protocol, c.SrcAddr, c.SrcPort, c.DstAddr, c.DstPort, c.FrameCount, c.ByteCount)
	}
	return len(convs), int64(buf.Len()), nil
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
	return gowireshark.OpenSessionContext(context.Background(), r.pcap)
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
