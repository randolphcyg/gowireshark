package gowireshark

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/bytedance/sonic"
	"github.com/pkg/errors"
)

var (
	// ErrParseFrame reports malformed layer data returned by libwireshark.
	ErrParseFrame = errors.New("failed to parse frame")
	// ErrLayerNotFound reports that a requested protocol layer is absent.
	ErrLayerNotFound = errors.New("layer not found")
)

// Layers contains the raw Wireshark protocol tree keyed by layer name.
type Layers map[string]any

// FrameData is the parsed dissection result for one frame.
type FrameData struct {
	Index      string   `json:"_index"`
	Layers     Layers   `json:"layers"` // source
	BaseLayers struct { // common layers
		Frame *Frame  `json:"frame,omitempty"`
		WSCol *WSCol  `json:"wsCol,omitempty"`
		ETH   *ETH    `json:"eth,omitempty"`
		IP    *IP     `json:"ip,omitempty"`
		UDP   *UDP    `json:"udp,omitempty"`
		TCP   *TCP    `json:"tcp,omitempty"`
		HTTP  []*HTTP `json:"http,omitempty"`
		DNS   *DNS    `json:"dns,omitempty"`
	} `json:"baseLayers"`
	// CustomLayers holds results from registered custom protocol parsers.
	// Key is the protocol name, value is the parsed result.
	// Only populated when a registry is supplied with WithRegistry.
	CustomLayers map[string]any `json:"customLayers,omitempty"`
}

// --- Layer map helpers ---
// These avoid the Marshal→Unmarshal round-trip by reading directly from map[string]any.

// getLayerMap retrieves a layer's raw map from the Layers.
func getLayerMap(l Layers, key string) (map[string]any, error) {
	src, ok := l[key]
	if !ok {
		return nil, errors.Wrap(ErrLayerNotFound, key)
	}
	m, ok := src.(map[string]any)
	if !ok {
		return nil, errors.Wrapf(ErrParseFrame, "%s: unexpected type %T", key, src)
	}
	return m, nil
}

// mapStr extracts a string value from a map.
func mapStr(m map[string]any, key string) string {
	if v, ok := m[key]; ok {
		switch s := v.(type) {
		case string:
			return s
		case float64:
			return strconv.FormatFloat(s, 'f', -1, 64)
		case json.Number:
			return s.String()
		}
	}
	return ""
}

// mapInt extracts an integer value from a map (wireshark outputs numbers as strings).
func mapInt(m map[string]any, key string) int {
	v, _ := strconv.Atoi(mapStr(m, key))
	return v
}

// mapFloat64 extracts a float64 value from a map.
func mapFloat64(m map[string]any, key string) float64 {
	v, _ := strconv.ParseFloat(mapStr(m, key), 64)
	return v
}

// mapBool extracts a boolean value from a map.
func mapBool(m map[string]any, key string) bool {
	v, _ := strconv.ParseBool(mapStr(m, key))
	return v
}

// mapStrSlice extracts a string slice from a map field that can be a single string or []any.
func mapStrSlice(m map[string]any, key string) *[]string {
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}
	switch val := v.(type) {
	case string:
		return &[]string{val}
	case []any:
		result := make([]string, 0, len(val))
		for _, item := range val {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return &result
	}
	return nil
}

// --- Frame ---

// Frame contains common fields from Wireshark's frame layer.
type Frame struct {
	SectionNumber      int     `json:"frame.section_number"`
	InterfaceID        int     `json:"frame.interface_id"`
	EncapType          string  `json:"frame.encap_type"`
	Time               string  `json:"frame.time"`
	TimeUTC            string  `json:"frame.time_utc"`
	TimeEpoch          float64 `json:"frame.time_epoch"`
	OffsetShift        string  `json:"frame.offset_shift"`
	TimeDelta          string  `json:"frame.time_delta"`
	TimeDeltaDisplayed string  `json:"frame.time_delta_displayed"`
	TimeRelative       string  `json:"frame.time_relative"`
	Number             int     `json:"frame.number"`
	Len                int     `json:"frame.len"`
	CapLen             int     `json:"frame.cap_len"`
	Marked             bool    `json:"frame.marked"`
	Ignored            bool    `json:"frame.ignored"`
	Protocols          string  `json:"frame.protocols"`
	Length             int     `json:"frame.length"`
	Checksum           string  `json:"frame.checksum"`
	CaptureLength      int     `json:"frame.capture_length"`
	FrameType          string  `json:"frame.type"`
}

func (l Layers) Frame() (*Frame, error) {
	m, err := getLayerMap(l, "frame")
	if err != nil {
		return nil, err
	}

	return &Frame{
		SectionNumber:      mapInt(m, "frame.section_number"),
		InterfaceID:        mapInt(m, "frame.interface_id"),
		EncapType:          mapStr(m, "frame.encap_type"),
		Time:               mapStr(m, "frame.time"),
		TimeUTC:            mapStr(m, "frame.time_utc"),
		TimeEpoch:          mapFloat64(m, "frame.time_epoch"),
		OffsetShift:        mapStr(m, "frame.offset_shift"),
		TimeDelta:          mapStr(m, "frame.time_delta"),
		TimeDeltaDisplayed: mapStr(m, "frame.time_delta_displayed"),
		TimeRelative:       mapStr(m, "frame.time_relative"),
		Number:             mapInt(m, "frame.number"),
		Len:                mapInt(m, "frame.len"),
		CapLen:             mapInt(m, "frame.cap_len"),
		Marked:             mapBool(m, "frame.marked"),
		Ignored:            mapBool(m, "frame.ignored"),
		Protocols:          mapStr(m, "frame.protocols"),
		Length:             mapInt(m, "frame.length"),
		Checksum:           mapStr(m, "frame.checksum"),
		CaptureLength:      mapInt(m, "frame.capture_length"),
		FrameType:          mapStr(m, "frame.type"),
	}, nil
}

// --- WSCol ---

// WSCol contains Wireshark summary-column values from the _ws.col layer.
type WSCol struct {
	Num       int    `json:"_ws.col.number"`
	DefSrc    string `json:"_ws.col.def_src"`
	DefDst    string `json:"_ws.col.def_dst"`
	Protocol  string `json:"_ws.col.protocol"`
	PacketLen int    `json:"_ws.col.packet_length"`
	Info      string `json:"_ws.col.info"`
}

func (l Layers) WSCol() (*WSCol, error) {
	m, err := getLayerMap(l, "_ws.col")
	if err != nil {
		return nil, err
	}

	return &WSCol{
		Num:       mapInt(m, "_ws.col.number"),
		DefSrc:    mapStr(m, "_ws.col.def_src"),
		DefDst:    mapStr(m, "_ws.col.def_dst"),
		Protocol:  mapStr(m, "_ws.col.protocol"),
		PacketLen: mapInt(m, "_ws.col.packet_length"),
		Info:      mapStr(m, "_ws.col.info"),
	}, nil
}

// --- ETH ---

// ETH contains Ethernet layer fields.
type ETH struct {
	Src            string `json:"eth.src"`
	SrcResolved    string `json:"eth.src_tree.addr_resolved"`
	SrcOui         int    `json:"eth.src_tree.addr.oui"`
	SrcOuiResolved string `json:"eth.src_tree.addr.oui_resolved"`
	SrcIG          int    `json:"eth.src_tree.ig"`
	SrcLG          int    `json:"eth.src_tree.lg"`
	Dst            string `json:"eth.dst"`
	DstResolved    string `json:"eth.dst_tree.addr_resolved"`
	DstOui         int    `json:"eth.dst_tree.addr.oui"`
	DstOuiResolved string `json:"eth.dst_tree.addr.oui_resolved"`
	DstIG          int    `json:"eth.dst_tree.ig"`
	DstLG          int    `json:"eth.dst_tree.lg"`
	Type           string `json:"eth.type"`
}

func (l Layers) ETH() (*ETH, error) {
	m, err := getLayerMap(l, "eth")
	if err != nil {
		return nil, err
	}

	return &ETH{
		Src:            mapStr(m, "eth.src"),
		SrcResolved:    mapStr(m, "eth.src_tree.addr_resolved"),
		SrcOui:         mapInt(m, "eth.src_tree.addr.oui"),
		SrcOuiResolved: mapStr(m, "eth.src_tree.addr.oui_resolved"),
		SrcIG:          mapInt(m, "eth.src_tree.ig"),
		SrcLG:          mapInt(m, "eth.src_tree.lg"),
		Dst:            mapStr(m, "eth.dst"),
		DstResolved:    mapStr(m, "eth.dst_tree.addr_resolved"),
		DstOui:         mapInt(m, "eth.dst_tree.addr.oui"),
		DstOuiResolved: mapStr(m, "eth.dst_tree.addr.oui_resolved"),
		DstIG:          mapInt(m, "eth.dst_tree.ig"),
		DstLG:          mapInt(m, "eth.dst_tree.lg"),
		Type:           mapStr(m, "eth.type"),
	}, nil
}

// --- IP ---

// IP contains IPv4 layer fields.
type IP struct {
	HdrLen         int    `json:"ip.hdr_len"`
	ID             string `json:"ip.id"`
	Proto          string `json:"ip.proto"`
	Checksum       string `json:"ip.checksum"`
	Src            string `json:"ip.src"`
	Dst            string `json:"ip.dst"`
	Len            int    `json:"ip.len"`
	DsField        string `json:"ip.dsfield"`
	Flags          string `json:"ip.flags"`
	FragOffset     int    `json:"ip.frag_offset"`
	Ttl            int    `json:"ip.ttl"`
	Version        int    `json:"ip.version"`
	ChecksumStatus string `json:"ip.checksum.status"`
	Options        string `json:"ip.options,omitempty"`
	IPHeaderType   string `json:"ip.header_type"`
}

func (l Layers) IP() (*IP, error) {
	m, err := getLayerMap(l, "ip")
	if err != nil {
		return nil, err
	}

	return &IP{
		HdrLen:         mapInt(m, "ip.hdr_len"),
		ID:             mapStr(m, "ip.id"),
		Proto:          mapStr(m, "ip.proto"),
		Checksum:       mapStr(m, "ip.checksum"),
		Src:            mapStr(m, "ip.src"),
		Dst:            mapStr(m, "ip.dst"),
		Len:            mapInt(m, "ip.len"),
		DsField:        mapStr(m, "ip.dsfield"),
		Flags:          mapStr(m, "ip.flags"),
		FragOffset:     mapInt(m, "ip.frag_offset"),
		Ttl:            mapInt(m, "ip.ttl"),
		Version:        mapInt(m, "ip.version"),
		ChecksumStatus: mapStr(m, "ip.checksum.status"),
		Options:        mapStr(m, "ip.options"),
		IPHeaderType:   mapStr(m, "ip.header_type"),
	}, nil
}

// --- UDP ---

// UDP contains UDP layer fields.
type UDP struct {
	SrcPort        int       `json:"udp.srcport"`
	DstPort        int       `json:"udp.dstport"`
	Length         int       `json:"udp.length"`
	ChecksumStatus string    `json:"udp.checksum.status"`
	Checksum       string    `json:"udp.checksum"`
	Port           *[]string `json:"udp.port"`
	Stream         int       `json:"udp.stream"`
	DataLength     int       `json:"udp.data_length"`
	Timestamp      string    `json:"udp.timestamp"`
	Payload        string    `json:"udp.payload"`
}

func (l Layers) UDP() (*UDP, error) {
	m, err := getLayerMap(l, "udp")
	if err != nil {
		return nil, err
	}

	return &UDP{
		SrcPort:        mapInt(m, "udp.srcport"),
		DstPort:        mapInt(m, "udp.dstport"),
		Length:         mapInt(m, "udp.length"),
		ChecksumStatus: mapStr(m, "udp.checksum.status"),
		Checksum:       mapStr(m, "udp.checksum"),
		Port:           mapStrSlice(m, "udp.port"),
		Stream:         mapInt(m, "udp.stream"),
		DataLength:     mapInt(m, "udp.data_length"),
		Timestamp:      mapStr(m, "udp.timestamp"),
		Payload:        mapStr(m, "udp.payload"),
	}, nil
}

// --- TCP ---

// TCP contains TCP layer fields.
type TCP struct {
	SrcPort        int       `json:"tcp.srcport"`
	DstPort        int       `json:"tcp.dstport"`
	SeqRaw         int       `json:"tcp.seq_raw"`
	AckRaw         int       `json:"tcp.ack_raw"`
	Seq            int       `json:"tcp.seq"`
	NextSeq        int       `json:"tcp.next_seq"`
	UrgentPointer  int       `json:"tcp.urgent_pointer"`
	HdrLen         int       `json:"tcp.hdr_len"`
	Len            int       `json:"tcp.len"`
	WinSize        int       `json:"tcp.window_size"`
	WinSizeVal     int       `json:"tcp.window_size_value"`
	ChecksumStatus string    `json:"tcp.checksum.status"`
	Checksum       string    `json:"tcp.checksum"`
	Flags          string    `json:"tcp.flags"`
	Port           *[]string `json:"tcp.port"`
	Stream         int       `json:"tcp.stream"`
	Payload        string    `json:"tcp.payload"`
	Completeness   string    `json:"tcp.completeness"`
}

func (l Layers) TCP() (*TCP, error) {
	m, err := getLayerMap(l, "tcp")
	if err != nil {
		return nil, err
	}

	return &TCP{
		SrcPort:        mapInt(m, "tcp.srcport"),
		DstPort:        mapInt(m, "tcp.dstport"),
		SeqRaw:         mapInt(m, "tcp.seq_raw"),
		AckRaw:         mapInt(m, "tcp.ack_raw"),
		Seq:            mapInt(m, "tcp.seq"),
		NextSeq:        mapInt(m, "tcp.next_seq"),
		UrgentPointer:  mapInt(m, "tcp.urgent_pointer"),
		HdrLen:         mapInt(m, "tcp.hdr_len"),
		Len:            mapInt(m, "tcp.len"),
		WinSize:        mapInt(m, "tcp.window_size"),
		WinSizeVal:     mapInt(m, "tcp.window_size_value"),
		ChecksumStatus: mapStr(m, "tcp.checksum.status"),
		Checksum:       mapStr(m, "tcp.checksum"),
		Flags:          mapStr(m, "tcp.flags"),
		Port:           mapStrSlice(m, "tcp.port"),
		Stream:         mapInt(m, "tcp.stream"),
		Payload:        mapStr(m, "tcp.payload"),
		Completeness:   mapStr(m, "tcp.completeness"),
	}, nil
}

// --- HTTP ---

// HTTP contains HTTP layer fields.
type HTTP struct {
	Date   string `json:"http.date"`
	Host   string `json:"http.host"`
	Server string `json:"http.server"`
	Time   string `json:"http.time"`

	Request        string    `json:"http.request"`
	RequestLine    *[]string `json:"http.request.line"`
	RequestIn      string    `json:"http.request_in"`
	RequestUri     string    `json:"http.request.uri"`
	RequestFullUri string    `json:"http.request.full_uri"`

	Response         string    `json:"http.response"`
	ResponseVersion  string    `json:"http.response.version"`
	ResponseCode     string    `json:"http.response.code"`
	ResponseCodeDesc string    `json:"http.response.code.desc"`
	ResponsePhrase   string    `json:"http.response.phrase"`
	ResponseLine     *[]string `json:"http.response.line"`
	ResponseUrl      string    `json:"http.response_for.uri"`
	ResponseNumber   string    `json:"http.response_number"`

	UserAgent           string `json:"http.user_agent"`
	Accept              string `json:"http.accept"`
	LastModified        string `json:"http.last_modified"`
	ContentType         string `json:"http.content_type"`
	ContentLengthHeader string `json:"http.content_length_header"`
	ContentLength       string `json:"http.content_length"`
	FileData            string `json:"http.file_data"`

	Connection       string `json:"http.connection"`
	CacheControl     string `json:"http.cache_control"`
	Cookie           string `json:"http.cookie"`
	AcceptEncoding   string `json:"http.accept_encoding"`
	AcceptLanguage   string `json:"http.accept_language"`
	Referer          string `json:"http.referer"`
	TransferEncoding string `json:"http.transfer_encoding"`
	Origin           string `json:"http.origin"`
}

func (l Layers) HTTP() ([]*HTTP, error) {
	src, ok := l["http"]
	if !ok {
		return nil, errors.Wrap(ErrLayerNotFound, "http")
	}

	switch v := src.(type) {
	case map[string]any:
		h, err := parseSingleHTTP(v)
		if err != nil {
			return nil, err
		}
		return []*HTTP{h}, nil
	case []any:
		return parseMultipleHTTP(v)
	default:
		return nil, errors.Wrapf(ErrParseFrame, "HTTP: unexpected type %T", src)
	}
}

func parseSingleHTTP(m map[string]any) (*HTTP, error) {
	h := &HTTP{
		Date:                mapStr(m, "http.date"),
		Host:                mapStr(m, "http.host"),
		UserAgent:           mapStr(m, "http.user_agent"),
		Accept:              mapStr(m, "http.accept"),
		LastModified:        mapStr(m, "http.last_modified"),
		ContentType:         mapStr(m, "http.content_type"),
		ContentLengthHeader: mapStr(m, "http.content_length_header"),
		ContentLength:       mapStr(m, "http.content_length"),
		FileData:            mapStr(m, "http.file_data"),
		Server:              mapStr(m, "http.server"),
		Time:                mapStr(m, "http.time"),

		Request:        mapStr(m, "http.request"),
		RequestLine:    mapStrSlice(m, "http.request.line"),
		RequestIn:      mapStr(m, "http.request_in"),
		RequestUri:     mapStr(m, "http.request.uri"),
		RequestFullUri: mapStr(m, "http.request.full_uri"),

		Response:       mapStr(m, "http.response"),
		ResponseCode:   mapStr(m, "http.response.code"),
		ResponsePhrase: mapStr(m, "http.response.phrase"),
		ResponseLine:   mapStrSlice(m, "http.response.line"),
		ResponseUrl:    mapStr(m, "http.response_for.uri"),
		ResponseNumber: mapStr(m, "http.response_number"),

		Connection:       mapStr(m, "http.connection"),
		CacheControl:     mapStr(m, "http.cache_control"),
		Cookie:           mapStr(m, "http.cookie"),
		AcceptEncoding:   mapStr(m, "http.accept_encoding"),
		AcceptLanguage:   mapStr(m, "http.accept_language"),
		Referer:          mapStr(m, "http.referer"),
		TransferEncoding: mapStr(m, "http.transfer_encoding"),
		Origin:           mapStr(m, "http.origin"),
	}

	// Extract response version/code/desc from dynamic keys like "HTTP/1.1 200 OK\r\n"
	for key, value := range m {
		if strings.HasPrefix(key, "HTTP/") {
			if nested, ok := value.(map[string]any); ok {
				if v := mapStr(nested, "http.response.version"); v != "" {
					h.ResponseVersion = v
				}
				if v := mapStr(nested, "http.response.code"); v != "" {
					h.ResponseCode = v
				}
				if v := mapStr(nested, "http.response.code.desc"); v != "" {
					h.ResponseCodeDesc = v
				}
				if v := mapStr(nested, "http.response.phrase"); v != "" {
					h.ResponsePhrase = v
				}
			}
			break // Only one HTTP status line per response
		}
	}

	return h, nil
}

func parseMultipleHTTP(src []any) ([]*HTTP, error) {
	httpLayers := make([]*HTTP, 0, len(src))
	for _, item := range src {
		itemMap, ok := item.(map[string]any)
		if !ok {
			return nil, errors.Wrapf(ErrParseFrame, "HTTP: unexpected type %T in array", item)
		}
		h, err := parseSingleHTTP(itemMap)
		if err != nil {
			return nil, err
		}
		httpLayers = append(httpLayers, h)
	}
	return httpLayers, nil
}

// --- DNS ---

// DNSQuery contains one DNS question record.
type DNSQuery struct {
	DNSQryName     string `json:"dns.qry.name"`
	DNSQryNameLen  string `json:"dns.qry.name.len"`
	DNSCountLabels string `json:"dns.count.labels"`
	DNSQryType     string `json:"dns.qry.type"`
	DNSQryClass    string `json:"dns.qry.class"`
}

// DNSAnswer contains one DNS answer record.
type DNSAnswer struct {
	DNSA         string `json:"dns.a"`
	DNSRespName  string `json:"dns.resp.name"`
	DNSRespType  string `json:"dns.resp.type"`
	DNSRespClass string `json:"dns.resp.class"`
	DNSRespTtl   string `json:"dns.resp.ttl"`
	DNSRespLen   string `json:"dns.resp.len"`
}

// DNS contains DNS layer fields.
type DNS struct {
	DNSID        string      `json:"dns.id"`
	Flags        string      `json:"dns.flags"`
	QueriesCount int         `json:"dns.count.queries"`
	Queries      []DNSQuery  `json:"Queries"`
	AnswersCount int         `json:"dns.count.answers"`
	Answers      []DNSAnswer `json:"Answers"`
}

func (l Layers) DNS() (*DNS, error) {
	m, err := getLayerMap(l, "dns")
	if err != nil {
		return nil, err
	}

	queriesCount := mapInt(m, "dns.count.queries")
	answersCount := mapInt(m, "dns.count.answers")

	queries := parseDNSEntries[DNSQuery](m, "Queries")
	answers := parseDNSEntries[DNSAnswer](m, "Answers")

	return &DNS{
		DNSID:        mapStr(m, "dns.id"),
		Flags:        mapStr(m, "dns.flags"),
		QueriesCount: queriesCount,
		Queries:      queries,
		AnswersCount: answersCount,
		Answers:      answers,
	}, nil
}

// parseDNSEntries generically parses DNS query/answer entries from a map field.
func parseDNSEntries[T any](m map[string]any, key string) []T {
	raw, ok := m[key]
	if !ok || raw == nil {
		return nil
	}

	rawMap, ok := raw.(map[string]any)
	if !ok {
		return nil
	}

	results := make([]T, 0, len(rawMap))
	for _, v := range rawMap {
		jsonBytes, err := sonic.Marshal(v)
		if err != nil {
			continue
		}
		var entry T
		if err := sonic.Unmarshal(jsonBytes, &entry); err != nil {
			continue
		}
		results = append(results, entry)
	}
	return results
}

// --- parseFieldAsArray (kept for backward compatibility with custom parsers) ---

// parseFieldAsArray handles single value or multiple value JSON fields.
func parseFieldAsArray(raw json.RawMessage) (*[]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}

	var singleValue string
	if sonic.Unmarshal(raw, &singleValue) == nil {
		return &[]string{singleValue}, nil
	}

	var multiValue []string
	if sonic.Unmarshal(raw, &multiValue) == nil {
		return &multiValue, nil
	}

	return nil, fmt.Errorf("fail to parse field as array")
}
