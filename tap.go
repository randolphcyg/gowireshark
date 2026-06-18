package gowireshark

/*
#include "bridge.h"
#include "offline.h"

// Forward declaration of the Go exported callback
extern int onFrameCallback(char *json, int len, int err);

static int call_get_tap_conversations_cb(char *filter, char *conv_type) {
    return get_tap_conversations_cb(filter, conv_type, onFrameCallback);
}

static int call_get_tap_endpoints_cb(char *filter, char *endpoint_type) {
    return get_tap_endpoints_cb(filter, endpoint_type, onFrameCallback);
}

static int call_get_service_response_times_cb(char *filter, char *protocol) {
    return get_service_response_times_cb(filter, protocol, onFrameCallback);
}

static int call_get_proto_hierarchy_cb(char *filter_str) {
    return get_proto_hierarchy_cb(filter_str, onFrameCallback);
}

static int call_get_io_stats_cb(char *filter_str, double interval) {
    return get_io_stats_cb(filter_str, interval, onFrameCallback);
}
*/
import "C"
import (
	"context"
	"time"
	"unsafe"

	"github.com/bytedance/sonic"
	"github.com/pkg/errors"
)

// TapConversation is STABLE.
// TapConversation describes one directional conversation from libwireshark's tap system.
type TapConversation struct {
	Type         string  `json:"type"`
	Addr1        string  `json:"addr1"`
	Port1        uint32  `json:"port1,omitempty"`
	Addr2        string  `json:"addr2"`
	Port2        uint32  `json:"port2,omitempty"`
	PacketsAB    uint64  `json:"packetsAB"`
	BytesAB      uint64  `json:"bytesAB"`
	PacketsBA    uint64  `json:"packetsBA"`
	BytesBA      uint64  `json:"bytesBA"`
	TotalPackets uint64  `json:"totalPackets"`
	TotalBytes   uint64  `json:"totalBytes"`
	StartTime    float64 `json:"startTime"`
	Duration     float64 `json:"duration"`
}

// TapEndpoint is STABLE.
// TapEndpoint describes one endpoint from libwireshark's tap system.
type TapEndpoint struct {
	Type    string `json:"type"`
	Address string `json:"address"`
	Port    uint32 `json:"port,omitempty"`
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

var supportedConvTypes = map[string]bool{
	"eth": true,
	"ip":  true,
	"tcp": true,
	"udp": true,
}

// TapConversations returns Wireshark conversation statistics for the given type.
func TapConversations(path string, convType string, opts ...Option) ([]TapConversation, error) {
	return TapConversationsContext(context.Background(), path, convType, opts...)
}

// TapConversationsContext returns Wireshark conversation statistics using the
// provided context for session acquisition.
func TapConversationsContext(ctx context.Context, path string, convType string, opts ...Option) ([]TapConversation, error) {
	s, err := OpenSessionContext(ctx, path, opts...)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return s.TapConversations(convType, Query{Filter: extractFilter(opts)})
}

// TapEndpoints returns Wireshark endpoint statistics for the given type.
func TapEndpoints(path string, endpointType string, opts ...Option) ([]TapEndpoint, error) {
	return TapEndpointsContext(context.Background(), path, endpointType, opts...)
}

// TapEndpointsContext returns Wireshark endpoint statistics using the provided
// context for session acquisition.
func TapEndpointsContext(ctx context.Context, path string, endpointType string, opts ...Option) ([]TapEndpoint, error) {
	s, err := OpenSessionContext(ctx, path, opts...)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return s.TapEndpoints(endpointType, Query{Filter: extractFilter(opts)})
}

func tapConversationsFromActive(convType string, filter string) ([]TapConversation, error) {
	if !supportedConvTypes[convType] {
		return nil, errors.Wrapf(ErrUnsupportedProtocol, "conversation type %q (must be eth/ip/tcp/udp)", convType)
	}
	if filter != "" {
		if err := ValidateFilter(filter); err != nil {
			return nil, err
		}
	}

	var out []TapConversation
	var parseErr error

	globalFrameSink = func(jsonBytes []byte) bool {
		if err := sonic.Unmarshal(jsonBytes, &out); err != nil {
			parseErr = err
			return false
		}
		return true
	}
	defer cleanupGlobalState()

	cFilter := C.CString(filter)
	cType := C.CString(convType)
	defer C.free(unsafe.Pointer(cFilter))
	defer C.free(unsafe.Pointer(cType))

	if ret := C.call_get_tap_conversations_cb(cFilter, cType); ret != 0 {
		return out, errors.Wrapf(ErrReadCaptureFile, "conversation tap failed: %d", int(ret))
	}
	if parseErr != nil {
		return out, parseErr
	}
	return out, nil
}

func tapEndpointsFromActive(endpointType string, filter string) ([]TapEndpoint, error) {
	if !supportedConvTypes[endpointType] {
		return nil, errors.Wrapf(ErrUnsupportedProtocol, "endpoint type %q (must be eth/ip/tcp/udp)", endpointType)
	}
	if filter != "" {
		if err := ValidateFilter(filter); err != nil {
			return nil, err
		}
	}

	var out []TapEndpoint
	var parseErr error

	globalFrameSink = func(jsonBytes []byte) bool {
		if err := sonic.Unmarshal(jsonBytes, &out); err != nil {
			parseErr = err
			return false
		}
		return true
	}
	defer cleanupGlobalState()

	cFilter := C.CString(filter)
	cType := C.CString(endpointType)
	defer C.free(unsafe.Pointer(cFilter))
	defer C.free(unsafe.Pointer(cType))

	if ret := C.call_get_tap_endpoints_cb(cFilter, cType); ret != 0 {
		return out, errors.Wrapf(ErrReadCaptureFile, "endpoint tap failed: %d", int(ret))
	}
	if parseErr != nil {
		return out, parseErr
	}
	return out, nil
}

// SRTSummary is STABLE.
// SRTSummary describes one procedure's response-time statistics.
type SRTSummary struct {
	Protocol  string  `json:"protocol"`
	Procedure string  `json:"procedure"`
	Calls     uint32  `json:"calls"`
	Min       float64 `json:"min"`
	Max       float64 `json:"max"`
	Avg       float64 `json:"avg"`
	Total     float64 `json:"total"`
}

func hasSrtTable(protocol string) bool {
	cProto := C.CString(protocol)
	defer C.free(unsafe.Pointer(cProto))
	return C.has_srt_table(cProto) != 0
}

// SupportsServiceResponseTimes reports whether a protocol has an SRT
// (Service Response Time) table registered in the current libwireshark
// runtime.
func SupportsServiceResponseTimes(protocol string) bool {
	return hasSrtTable(protocol)
}

// ProtocolHierarchy returns Wireshark protocol hierarchy statistics.
func ProtocolHierarchy(path string, opts ...Option) ([]ProtocolHierarchyEntry, error) {
	return ProtocolHierarchyContext(context.Background(), path, opts...)
}

// ProtocolHierarchyContext returns Wireshark protocol hierarchy statistics using
// the provided context for session acquisition.
func ProtocolHierarchyContext(ctx context.Context, path string, opts ...Option) ([]ProtocolHierarchyEntry, error) {
	s, err := OpenSessionContext(ctx, path, opts...)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return s.ProtocolHierarchy(Query{Filter: extractFilter(opts)})
}

// ServiceResponseTimes returns service response time statistics for a protocol.
func ServiceResponseTimes(path string, protocol string, opts ...Option) ([]SRTSummary, error) {
	return ServiceResponseTimesContext(context.Background(), path, protocol, opts...)
}

// ServiceResponseTimesContext returns service response time statistics using the
// provided context for session acquisition.
func ServiceResponseTimesContext(ctx context.Context, path string, protocol string, opts ...Option) ([]SRTSummary, error) {
	s, err := OpenSessionContext(ctx, path, opts...)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return s.ServiceResponseTimes(protocol, Query{Filter: extractFilter(opts)})
}

func serviceResponseTimesFromActive(protocol string, filter string) ([]SRTSummary, error) {
	if !hasSrtTable(protocol) {
		return nil, errors.Wrapf(ErrUnsupportedProtocol, "SRT protocol %q has no registered SRT table", protocol)
	}
	if filter != "" {
		if err := ValidateFilter(filter); err != nil {
			return nil, err
		}
	}

	var out []SRTSummary
	var parseErr error

	globalFrameSink = func(jsonBytes []byte) bool {
		if err := sonic.Unmarshal(jsonBytes, &out); err != nil {
			parseErr = err
			return false
		}
		return true
	}
	defer cleanupGlobalState()

	cFilter := C.CString(filter)
	cProto := C.CString(protocol)
	defer C.free(unsafe.Pointer(cFilter))
	defer C.free(unsafe.Pointer(cProto))

	if ret := C.call_get_service_response_times_cb(cFilter, cProto); ret != 0 {
		return out, errors.Wrapf(ErrReadCaptureFile, "SRT tap failed: %d", int(ret))
	}
	if parseErr != nil {
		return out, parseErr
	}
	return out, nil
}

// ProtocolHierarchyEntry is STABLE.
// ProtocolHierarchyEntry statistics entry for one protocol in the protocol hierarchy
type ProtocolHierarchyEntry struct {
	Protocol string `json:"protocol"`
	Packets  uint64 `json:"packets"`
	Bytes    uint64 `json:"bytes"`
}

func protocolHierarchyFromActive(filter string) ([]ProtocolHierarchyEntry, error) {
	if filter != "" {
		if err := ValidateFilter(filter); err != nil {
			return nil, err
		}
	}

	out := make([]ProtocolHierarchyEntry, 0)
	var parseErr error

	globalFrameSink = func(jsonBytes []byte) bool {
		var entry ProtocolHierarchyEntry
		if err := sonic.Unmarshal(jsonBytes, &entry); err != nil {
			parseErr = err
			return false
		}
		out = append(out, entry)
		return true
	}
	defer cleanupGlobalState()

	cFilter := C.CString(filter)
	defer C.free(unsafe.Pointer(cFilter))

	if ret := C.call_get_proto_hierarchy_cb(cFilter); ret != 0 {
		if parseErr != nil {
			return nil, parseErr
		}
		return nil, errors.Wrap(ErrReadCaptureFile, "protocol hierarchy tap scan failed")
	}

	return out, nil
}

// IOStatBucket is STABLE.
type IOStatBucket struct {
	Time    float64 `json:"t"`
	Packets uint64  `json:"packets"`
	Bytes   uint64  `json:"bytes"`
}

func ioStatsFromActive(filter string, intervalSecs float64) ([]IOStatBucket, error) {
	if filter != "" {
		if err := ValidateFilter(filter); err != nil {
			return nil, err
		}
	}

	out := make([]IOStatBucket, 0)
	var parseErr error

	globalFrameSink = func(jsonBytes []byte) bool {
		var bucket IOStatBucket
		if err := sonic.Unmarshal(jsonBytes, &bucket); err != nil {
			parseErr = err
			return false
		}
		out = append(out, bucket)
		return true
	}
	defer cleanupGlobalState()

	cFilter := C.CString(filter)
	defer C.free(unsafe.Pointer(cFilter))

	ret := C.call_get_io_stats_cb(cFilter, C.double(intervalSecs))
	if parseErr != nil {
		return nil, parseErr
	}
	if ret < 0 {
		if ret == -2 {
			return nil, &DisplayFilterError{Filter: filter, Message: "filter compile failed"}
		}
		return nil, errors.Wrap(ErrReadCaptureFile, "io stats scan failed")
	}

	return out, nil
}

func IOStats(path string, interval time.Duration, opts ...Option) ([]IOStatBucket, error) {
	return IOStatsContext(context.Background(), path, interval, opts...)
}

// IOStatsContext returns IO statistics using the provided context for session
// acquisition.
func IOStatsContext(ctx context.Context, path string, interval time.Duration, opts ...Option) ([]IOStatBucket, error) {
	s, err := OpenSessionContext(ctx, path, opts...)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return s.IOStats(Query{Filter: extractFilter(opts)}, interval)
}
