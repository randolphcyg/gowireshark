package pkg

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/bytedance/sonic"
	"github.com/pkg/errors"
)

var (
	ErrParseFrame    = errors.New("fail to parse frame")
	ErrLayerNotFound = errors.New("layer not found")
)

type Layers map[string]any

// FrameData Dissect results of each frame of data
type FrameData struct {
	Index      string   `json:"_index"`
	Layers     Layers   `json:"layers"` // source
	BaseLayers struct { // common layers
		Frame *Frame
		WsCol *WsCol
		Eth   *Eth
		Ip    *Ip
		Udp   *Udp
		Tcp   *Tcp
		Http  []*Http
		Dns   *Dns
	}
}

// parseFieldAsArray handle Single value or multiple value
func parseFieldAsArray(raw json.RawMessage) (*[]string, error) {
	if len(raw) == 0 {
		return nil, nil // 如果字段缺失或为空，返回 nil
	}

	var singleValue string
	var multiValue []string

	// single value
	if sonic.Unmarshal(raw, &singleValue) == nil {
		return &[]string{singleValue}, nil
	}

	// multiple value
	if sonic.Unmarshal(raw, &multiValue) == nil {
		return &multiValue, nil
	}

	return nil, errors.New("fail to parse field")
}

// Frame wireshark frame
type Frame struct {
	// Common fields
	SectionNumber      int     `json:"frame.section_number"`       // Frame section number
	InterfaceID        int     `json:"frame.interface_id"`         // Interface ID for the frame
	EncapType          string  `json:"frame.encap_type"`           // Encapsulation type
	Time               string  `json:"frame.time"`                 // Timestamp of the frame
	TimeUTC            string  `json:"frame.time_utc"`             // UTC timestamp of the frame
	TimeEpoch          float64 `json:"frame.time_epoch"`           // Epoch time in seconds
	OffsetShift        string  `json:"frame.offset_shift"`         // Frame offset shift
	TimeDelta          string  `json:"frame.time_delta"`           // Time delta between frames
	TimeDeltaDisplayed string  `json:"frame.time_delta_displayed"` // Time delta displayed
	TimeRelative       string  `json:"frame.time_relative"`        // Time relative to the first frame
	Number             int     `json:"frame.number"`               // Frame number in the capture
	Len                int     `json:"frame.len"`                  // Length of the frame in bytes
	CapLen             int     `json:"frame.cap_len"`              // Captured length of the frame
	Marked             bool    `json:"frame.marked"`               // Whether the frame is marked
	Ignored            bool    `json:"frame.ignored"`              // Whether the frame is ignored
	Protocols          string  `json:"frame.protocols"`            // List of protocols used in the frame

	// Additional fields
	// These are specific to some frames and may not always be present.
	Length        int    `json:"frame.length"`         // Frame length (if different from Len)
	Checksum      string `json:"frame.checksum"`       // Checksum of the frame
	CaptureLength int    `json:"frame.capture_length"` // Length of the capture
	FrameType     string `json:"frame.type"`           // Type of the frame (e.g., Ethernet, IP)
}

func (l Layers) Frame() (frame any, err error) {
	src, ok := l["frame"]
	if !ok {
		return nil, errors.Wrap(ErrLayerNotFound, "frame")
	}

	type tmpFrame struct {
		SectionNumber      string `json:"frame.section_number"`
		InterfaceID        string `json:"frame.interface_id"`
		EncapType          string `json:"frame.encap_type"`
		Time               string `json:"frame.time"`
		TimeUTC            string `json:"frame.time_utc"`
		TimeEpoch          string `json:"frame.time_epoch"`
		OffsetShift        string `json:"frame.offset_shift"`
		TimeDelta          string `json:"frame.time_delta"`
		TimeDeltaDisplayed string `json:"frame.time_delta_displayed"`
		TimeRelative       string `json:"frame.time_relative"`
		Number             string `json:"frame.number"`
		Len                string `json:"frame.len"`
		CapLen             string `json:"frame.cap_len"`
		Marked             string `json:"frame.marked"`
		Ignored            string `json:"frame.ignored"`
		Protocols          string `json:"frame.protocols"`

		Length        string `json:"frame.length"`
		Checksum      string `json:"frame.checksum"`
		CaptureLength string `json:"frame.capture_length"`
		FrameType     string `json:"frame.type"`
	}

	var tmp tmpFrame

	jsonData, err := sonic.Marshal(src)
	if err != nil {
		return nil, errors.Wrapf(err, "frame: %s", ErrParseFrame)
	}

	err = sonic.Unmarshal(jsonData, &tmp)
	if err != nil {
		return nil, errors.Wrapf(err, "frame: %s", ErrParseFrame)
	}

	sectionNumber, _ := strconv.Atoi(tmp.SectionNumber)
	interfaceID, _ := strconv.Atoi(tmp.InterfaceID)
	num, _ := strconv.Atoi(tmp.Number)
	lenValue, _ := strconv.Atoi(tmp.Len)
	capLen, _ := strconv.Atoi(tmp.CapLen)
	marked, _ := strconv.ParseBool(tmp.Marked)
	ignored, _ := strconv.ParseBool(tmp.Ignored)
	timeEpoch, _ := strconv.ParseFloat(tmp.TimeEpoch, 64)
	length, _ := strconv.Atoi(tmp.Length)
	captureLength, _ := strconv.Atoi(tmp.CaptureLength)

	return &Frame{
		SectionNumber:      sectionNumber,
		InterfaceID:        interfaceID,
		EncapType:          tmp.EncapType,
		Time:               tmp.Time,
		TimeUTC:            tmp.TimeUTC,
		TimeEpoch:          timeEpoch,
		OffsetShift:        tmp.OffsetShift,
		TimeDelta:          tmp.TimeDelta,
		TimeDeltaDisplayed: tmp.TimeDeltaDisplayed,
		TimeRelative:       tmp.TimeRelative,
		Number:             num,
		Len:                lenValue,
		CapLen:             capLen,
		Marked:             marked,
		Ignored:            ignored,
		Protocols:          tmp.Protocols,
		Length:             length,
		Checksum:           tmp.Checksum,
		CaptureLength:      captureLength,
		FrameType:          tmp.FrameType,
	}, nil
}

// WsCol Wireshark column data structure (_ws.col)
type WsCol struct {
	// General fields
	Num       int    `json:"_ws.col.number"`        // Column number
	DefSrc    string `json:"_ws.col.def_src"`       // Default source (e.g., source address)
	DefDst    string `json:"_ws.col.def_dst"`       // Default destination (e.g., destination address)
	Protocol  string `json:"_ws.col.protocol"`      // Protocol (e.g., TCP, UDP, HTTP)
	PacketLen int    `json:"_ws.col.packet_length"` // Length of the packet (in bytes)
	Info      string `json:"_ws.col.info"`          // Additional information about the packet
}

func (l Layers) WsCol() (wsCol any, err error) {
	src, ok := l["_ws.col"]
	if !ok {
		return nil, errors.Wrap(ErrLayerNotFound, "_ws.col")
	}

	type tmpWsCol struct {
		Num       string `json:"_ws.col.number"`
		DefSrc    string `json:"_ws.col.def_src"`
		DefDst    string `json:"_ws.col.def_dst"`
		Protocol  string `json:"_ws.col.protocol"`
		PacketLen string `json:"_ws.col.packet_length"`
		Info      string `json:"_ws.col.info"`
	}
	var tmp tmpWsCol

	jsonData, err := sonic.Marshal(src)
	if err != nil {
		return nil, errors.Wrapf(err, "_ws.col: %s", ErrParseFrame)
	}

	err = sonic.Unmarshal(jsonData, &tmp)
	if err != nil {
		return nil, errors.Wrapf(err, "_ws.col: %s", ErrParseFrame)
	}

	num, err := strconv.Atoi(tmp.Num)
	packetLen, err := strconv.Atoi(tmp.PacketLen)

	return &WsCol{
		Num:       num,
		DefSrc:    tmp.DefSrc,
		DefDst:    tmp.DefDst,
		Protocol:  tmp.Protocol,
		PacketLen: packetLen,
		Info:      tmp.Info,
	}, nil
}

// Eth Wireshark ETH layer structure (frame.eth)
type Eth struct {
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

func (l Layers) Eth() (eth any, err error) {
	src, ok := l["eth"]
	if !ok {
		return nil, errors.Wrap(ErrLayerNotFound, "eth")
	}
	type tmpEth struct {
		Src            string `json:"eth.src"`
		SrcResolved    string `json:"eth.src_tree.addr_resolved"`
		SrcOui         string `json:"eth.src_tree.addr.oui"`
		SrcOuiResolved string `json:"eth.src_tree.addr.oui_resolved"`
		SrcIG          string `json:"eth.src_tree.ig"`
		SrcLG          string `json:"eth.src_tree.lg"`
		Dst            string `json:"eth.dst"`
		DstResolved    string `json:"eth.dst_tree.addr_resolved"`
		DstOui         string `json:"eth.dst_tree.addr.oui"`
		DstOuiResolved string `json:"eth.dst_tree.addr.oui_resolved"`
		DstIG          string `json:"eth.dst_tree.ig"`
		DstLG          string `json:"eth.dst_tree.lg"`
		Type           string `json:"eth.type"`
	}
	var tmp tmpEth

	jsonData, err := sonic.Marshal(src)
	if err != nil {
		return nil, errors.Wrapf(err, "eth: %s", ErrParseFrame)
	}

	err = sonic.Unmarshal(jsonData, &tmp)
	if err != nil {
		return nil, errors.Wrapf(err, "eth: %s", ErrParseFrame)
	}

	srcOui, err := strconv.Atoi(tmp.SrcOui)
	srcIG, err := strconv.Atoi(tmp.SrcIG)
	srcLG, err := strconv.Atoi(tmp.SrcLG)
	dstOui, err := strconv.Atoi(tmp.DstOui)
	dstIG, err := strconv.Atoi(tmp.DstIG)
	dstLG, err := strconv.Atoi(tmp.DstLG)

	return &Eth{
		Src:            tmp.Src,
		SrcResolved:    tmp.SrcResolved,
		SrcOui:         srcOui,
		SrcOuiResolved: tmp.SrcOuiResolved,
		SrcIG:          srcIG,
		SrcLG:          srcLG,
		Dst:            tmp.Dst,
		DstResolved:    tmp.DstResolved,
		DstOui:         dstOui,
		DstOuiResolved: tmp.DstOuiResolved,
		DstIG:          dstIG,
		DstLG:          dstLG,
		Type:           tmp.Type,
	}, nil
}

// Ip Wireshark IP layer structure (frame.ip)
type Ip struct {
	// Header Information
	HdrLen         int    `json:"ip.hdr_len"`         // Header length in 32-bit words
	ID             string `json:"ip.id"`              // Identification field
	Proto          string `json:"ip.proto"`           // Protocol used in the data portion (e.g., TCP, UDP)
	Checksum       string `json:"ip.checksum"`        // Header checksum for error checking
	Src            string `json:"ip.src"`             // Source IP address
	Dst            string `json:"ip.dst"`             // Destination IP address
	Len            int    `json:"ip.len"`             // Total length of the IP packet
	DsField        string `json:"ip.dsfield"`         // Differentiated Services field
	Flags          string `json:"ip.flags"`           // IP flags (e.g., DF, MF)
	FragOffset     int    `json:"ip.frag_offset"`     // Fragment offset for fragmentation
	Ttl            int    `json:"ip.ttl"`             // Time to live (TTL) value
	Version        int    `json:"ip.version"`         // IP version (e.g., IPv4, IPv6)
	ChecksumStatus string `json:"ip.checksum.status"` // Status of the checksum (valid or invalid)

	// Additional fields for better analysis (optional fields)
	Options      string `json:"ip.options,omitempty"` // Optional field for IP options if present
	IpHeaderType string `json:"ip.header_type"`       // Type of IP header (e.g., IPv4, IPv6)
}

func (l Layers) Ip() (ip any, err error) {
	src, ok := l["ip"]
	if !ok {
		return nil, errors.Wrap(ErrLayerNotFound, "ip")
	}

	type tmpIp struct {
		HdrLen         string `json:"ip.hdr_len"`
		ID             string `json:"ip.id"`
		Proto          string `json:"ip.proto"`
		Checksum       string `json:"ip.checksum"`
		Src            string `json:"ip.src"`
		Dst            string `json:"ip.dst"`
		Len            string `json:"ip.len"`
		DsField        string `json:"ip.dsfield"`
		Flags          string `json:"ip.flags"`
		FragOffset     string `json:"ip.frag_offset"`
		Ttl            string `json:"ip.ttl"`
		Version        string `json:"ip.version"`
		ChecksumStatus string `json:"ip.checksum.status"`
		Options        string `json:"ip.options"`
		IpHeaderType   string `json:"ip.header_type"`
	}
	var tmp tmpIp

	jsonData, err := sonic.Marshal(src)
	if err != nil {
		return nil, errors.Wrapf(err, "IP: %s", ErrParseFrame)
	}

	err = sonic.Unmarshal(jsonData, &tmp)
	if err != nil {
		return nil, errors.Wrapf(err, "IP: %s", ErrParseFrame)
	}

	hdrLen, _ := strconv.Atoi(tmp.HdrLen)
	length, _ := strconv.Atoi(tmp.Len)
	fragOffset, _ := strconv.Atoi(tmp.FragOffset)
	ttl, _ := strconv.Atoi(tmp.Ttl)
	version, _ := strconv.Atoi(tmp.Version)

	return &Ip{
		HdrLen:         hdrLen,
		ID:             tmp.ID,
		Proto:          tmp.Proto,
		Checksum:       tmp.Checksum,
		Src:            tmp.Src,
		Dst:            tmp.Dst,
		Len:            length,
		DsField:        tmp.DsField,
		Flags:          tmp.Flags,
		FragOffset:     fragOffset,
		Ttl:            ttl,
		Version:        version,
		ChecksumStatus: tmp.ChecksumStatus,
		Options:        tmp.Options,
		IpHeaderType:   tmp.IpHeaderType,
	}, nil
}

// Udp Wireshark UDP layer structure (frame.udp)
type Udp struct {
	// Source and Destination Ports
	SrcPort int `json:"udp.srcport"` // Source UDP port
	DstPort int `json:"udp.dstport"` // Destination UDP port

	// UDP Length and Checksum
	Length         int    `json:"udp.length"`          // Length of the UDP packet (excluding the header)
	ChecksumStatus string `json:"udp.checksum.status"` // Checksum validity status (valid or invalid)
	Checksum       string `json:"udp.checksum"`        // Checksum value for error checking

	// Port Information (list of ports involved)
	Port *[]string `json:"udp.port"` // List of ports involved in the UDP stream

	// Stream ID (if available, used for tracking UDP streams)
	Stream int `json:"udp.stream"` // Stream ID to uniquely identify the UDP stream

	// Additional Information
	DataLength int    `json:"udp.data_length"` // Length of UDP data (payload) excluding the header
	Timestamp  string `json:"udp.timestamp"`   // Timestamp for the UDP packet (if available)

	// Payload content (can be base64 encoded or raw bytes, depending on the need)
	Payload string `json:"udp.payload"` // Payload data of the UDP packet (optional, if available)
}

func (l Layers) Udp() (udp any, err error) {
	src, ok := l["udp"]
	if !ok {
		return nil, errors.Wrap(ErrLayerNotFound, "udp")
	}

	type tmpUdp struct {
		SrcPort        string          `json:"udp.srcport"`
		DstPort        string          `json:"udp.dstport"`
		Length         string          `json:"udp.length"`
		ChecksumStatus string          `json:"udp.checksum.status"`
		Port           json.RawMessage `json:"udp.port"`
		Checksum       string          `json:"udp.checksum"`
		Stream         string          `json:"udp.stream"`
		DataLength     string          `json:"udp.data_length"`
		Timestamp      string          `json:"udp.timestamp"`
		Payload        string          `json:"udp.payload"`
	}
	var tmp tmpUdp

	jsonData, err := sonic.Marshal(src)
	if err != nil {
		return nil, errors.Wrapf(err, "UDP: %s", ErrParseFrame)
	}

	err = sonic.Unmarshal(jsonData, &tmp)
	if err != nil {
		return nil, errors.Wrapf(err, "UDP: %s", ErrParseFrame)
	}

	srcPort, _ := strconv.Atoi(tmp.SrcPort)
	dstPort, _ := strconv.Atoi(tmp.DstPort)
	length, _ := strconv.Atoi(tmp.Length)
	stream, _ := strconv.Atoi(tmp.Stream)
	dataLength, _ := strconv.Atoi(tmp.DataLength)

	// Parse Port as array
	port, err := parseFieldAsArray(tmp.Port)
	if err != nil {
		return nil, fmt.Errorf("failed to parse udp.port: %v", err)
	}

	return &Udp{
		SrcPort:        srcPort,
		DstPort:        dstPort,
		Length:         length,
		ChecksumStatus: tmp.ChecksumStatus,
		Checksum:       tmp.Checksum,
		Port:           port,
		Stream:         stream,
		DataLength:     dataLength,
		Timestamp:      tmp.Timestamp,
		Payload:        tmp.Payload,
	}, nil
}

// Tcp Wireshark TCP layer structure (frame.tcp)
type Tcp struct {
	// Source and Destination Ports
	SrcPort int `json:"tcp.srcport"` // Source TCP port
	DstPort int `json:"tcp.dstport"` // Destination TCP port

	// TCP Sequence and Acknowledgment
	SeqRaw        int `json:"tcp.seq_raw"`        // Raw Sequence Number
	AckRaw        int `json:"tcp.ack_raw"`        // Raw Acknowledgment Number
	Seq           int `json:"tcp.seq"`            // Sequence Number
	NextSeq       int `json:"tcp.next_seq"`       // Next Sequence Number
	UrgentPointer int `json:"tcp.urgent_pointer"` // Urgent Pointer (if any)

	// Length and Window Size
	HdrLen     int `json:"tcp.hdr_len"`           // TCP Header Length
	Len        int `json:"tcp.len"`               // Total Length of the TCP segment
	WinSize    int `json:"tcp.window_size"`       // Window Size (size of the receive window)
	WinSizeVal int `json:"tcp.window_size_value"` // Window Size Value (actual size after scaling)

	// Checksum and Flags
	ChecksumStatus string `json:"tcp.checksum.status"` // Checksum validity status
	Checksum       string `json:"tcp.checksum"`        // TCP Checksum value
	Flags          string `json:"tcp.flags"`           // TCP Flags (SYN, ACK, FIN, etc.)

	// Stream Information and Payload
	Port    *[]string `json:"tcp.port"`    // List of ports involved in the TCP stream
	Stream  int       `json:"tcp.stream"`  // Stream ID to uniquely identify the TCP stream
	Payload string    `json:"tcp.payload"` // Payload data of the TCP segment

	// Completeness Information
	Completeness string `json:"tcp.completeness"` // Completeness of the TCP segment (e.g., full, partial)
}

func (l Layers) Tcp() (tcp any, err error) {
	src, ok := l["tcp"]
	if !ok {
		return nil, errors.Wrap(ErrLayerNotFound, "tcp")
	}

	type tmpTcp struct {
		SrcPort        string          `json:"tcp.srcport"`
		DstPort        string          `json:"tcp.dstport"`
		SeqRaw         string          `json:"tcp.seq_raw"`
		AckRaw         string          `json:"tcp.ack_raw"`
		Seq            string          `json:"tcp.seq"`
		NextSeq        string          `json:"tcp.next_seq"`
		UrgentPointer  string          `json:"tcp.urgent_pointer"`
		HdrLen         string          `json:"tcp.hdr_len"`
		Len            string          `json:"tcp.len"`
		WinSize        string          `json:"tcp.window_size"`
		WinSizeVal     string          `json:"tcp.window_size_value"`
		ChecksumStatus string          `json:"tcp.checksum.status"`
		Checksum       string          `json:"tcp.checksum"`
		Flags          string          `json:"tcp.flags"`
		Port           json.RawMessage `json:"tcp.port"`
		Stream         string          `json:"tcp.stream"`
		Payload        string          `json:"tcp.payload"`
		Completeness   string          `json:"tcp.completeness"`
	}
	var tmp tmpTcp

	// Convert source to JSON and then unmarshal it
	jsonData, err := sonic.Marshal(src)
	if err != nil {
		return nil, errors.Wrapf(err, "TCP: %s", ErrParseFrame)
	}

	err = sonic.Unmarshal(jsonData, &tmp)
	if err != nil {
		return nil, errors.Wrapf(err, "TCP: %s", ErrParseFrame)
	}

	// Parsing the fields in the order of the Tcp struct
	srcPort, _ := strconv.Atoi(tmp.SrcPort)
	dstPort, _ := strconv.Atoi(tmp.DstPort)
	seqRaw, _ := strconv.Atoi(tmp.SeqRaw)
	ackRaw, _ := strconv.Atoi(tmp.AckRaw)
	seq, _ := strconv.Atoi(tmp.Seq)
	nextSeq, _ := strconv.Atoi(tmp.NextSeq)
	urgentPointer, _ := strconv.Atoi(tmp.UrgentPointer)
	hdrLen, _ := strconv.Atoi(tmp.HdrLen)
	length, _ := strconv.Atoi(tmp.Len)
	winSize, _ := strconv.Atoi(tmp.WinSize)
	winSizeVal, _ := strconv.Atoi(tmp.WinSizeVal)
	checksumStatus := tmp.ChecksumStatus
	checksum := tmp.Checksum
	flags := tmp.Flags

	// Parse Port as array
	port, err := parseFieldAsArray(tmp.Port)
	if err != nil {
		return nil, errors.Wrapf(err, "TCP: %s", "fail to parse tcp.port")
	}

	// Parsing stream and payload
	stream, _ := strconv.Atoi(tmp.Stream)
	payload := tmp.Payload
	completeness := tmp.Completeness

	// Return Tcp struct with parsed fields
	return &Tcp{
		SrcPort:        srcPort,
		DstPort:        dstPort,
		SeqRaw:         seqRaw,
		AckRaw:         ackRaw,
		Seq:            seq,
		NextSeq:        nextSeq,
		UrgentPointer:  urgentPointer,
		HdrLen:         hdrLen,
		Len:            length,
		WinSize:        winSize,
		WinSizeVal:     winSizeVal,
		ChecksumStatus: checksumStatus,
		Checksum:       checksum,
		Flags:          flags,
		Port:           port,
		Stream:         stream,
		Payload:        payload,
		Completeness:   completeness,
	}, nil
}

// Http wireshark frame.http
type Http struct {
	// Common fields
	Date   string `json:"http.date"`   // Date of the HTTP request/response
	Host   string `json:"http.host"`   // Host header in HTTP request/response
	Server string `json:"http.server"` // Server information in HTTP response
	Time   string `json:"http.time"`   // Time of the HTTP request/response

	// Request fields
	Request        string    `json:"http.request"`          // HTTP request method (e.g., GET, POST)
	RequestLine    *[]string `json:"http.request.line"`     // The full request line (e.g., "GET / HTTP/1.1")
	RequestIn      string    `json:"http.request_in"`       // Time the request was received
	RequestUri     string    `json:"http.request.uri"`      // URI of the request
	RequestFullUri string    `json:"http.request.full_uri"` // Full URI of the request

	// Response fields
	Response         string    `json:"http.response"`           // HTTP response (e.g., "HTTP/1.1 200 OK")
	ResponseVersion  string    `json:"http.response.version"`   // HTTP version in the response
	ResponseCode     string    `json:"http.response.code"`      // Response status code (e.g., 200, 404)
	ResponseCodeDesc string    `json:"http.response.code.desc"` // Description of the response status code (e.g., "OK")
	ResponsePhrase   string    `json:"http.response.phrase"`    // Response phrase (e.g., "OK")
	ResponseLine     *[]string `json:"http.response.line"`      // Array of response lines
	ResponseUrl      string    `json:"http.response_for.uri"`   // URI for the response
	ResponseNumber   string    `json:"http.response_number"`    // Response number (if present)

	// Additional fields
	UserAgent           string `json:"http.user_agent"`            // User-Agent string
	Accept              string `json:"http.accept"`                // Accept header
	LastModified        string `json:"http.last_modified"`         // Last-Modified header
	ContentType         string `json:"http.content_type"`          // Content-Type header
	ContentLengthHeader string `json:"http.content_length_header"` // Content-Length header
	ContentLength       string `json:"http.content_length"`        // Content-Length value
	FileData            string `json:"http.file_data"`             // File data or body content

	// Additional headers
	Connection       string `json:"http.connection"`        // Connection header (e.g., "keep-alive")
	CacheControl     string `json:"http.cache_control"`     // Cache-Control header
	Cookie           string `json:"http.cookie"`            // Cookie header
	AcceptEncoding   string `json:"http.accept_encoding"`   // Accept-Encoding header
	AcceptLanguage   string `json:"http.accept_language"`   // Accept-Language header
	Referer          string `json:"http.referer"`           // Referer header
	TransferEncoding string `json:"http.transfer_encoding"` // Transfer-Encoding header
	Origin           string `json:"http.origin"`            // Origin header
}

func (l Layers) Http() (any, error) {
	src, ok := l["http"]
	if !ok {
		return nil, errors.Wrap(ErrLayerNotFound, "http")
	}

	switch v := src.(type) {
	case map[string]any:
		http, err := parseSingleHttp(v)
		if err != nil {
			return nil, err
		}
		return []*Http{http}, nil
	case []any:
		return parseMultipleHttp(v)
	default:
		return nil, errors.Wrapf(ErrParseFrame, "HTTP: unexpected type %T", src)
	}
}

func parseSingleHttp(src map[string]any) (*Http, error) {
	type tmpHttp struct {
		Date                string `json:"http.date"`
		Host                string `json:"http.host"`
		UserAgent           string `json:"http.user_agent"`
		Accept              string `json:"http.accept"`
		LastModified        string `json:"http.last_modified"`
		ContentType         string `json:"http.content_type"`
		ContentLengthHeader string `json:"http.content_length_header"`
		ContentLength       string `json:"http.content_length"`
		FileData            string `json:"http.file_data"`
		Server              string `json:"http.server"`
		Time                string `json:"http.time"`

		Request        string          `json:"http.request"`
		RequestLine    json.RawMessage `json:"http.request.line"`
		RequestIn      string          `json:"http.request_in"`
		RequestUri     string          `json:"http.request.uri"`
		RequestFullUri string          `json:"http.request.full_uri"`

		Response         string          `json:"http.response"`
		ResponseVersion  string          `json:"http.response.version"`
		ResponseCode     string          `json:"http.response.code"`
		ResponseCodeDesc string          `json:"http.response.code.desc"`
		ResponsePhrase   string          `json:"http.response.phrase"`
		ResponseLine     json.RawMessage `json:"http.response.line"`
		ResponseUrl      string          `json:"http.response_for.uri"`
		ResponseNumber   string          `json:"http.response_number"`

		Connection       string `json:"http.connection"`
		CacheControl     string `json:"http.cache_control"`
		Cookie           string `json:"http.cookie"`
		AcceptEncoding   string `json:"http.accept_encoding"`
		AcceptLanguage   string `json:"http.accept_language"`
		Referer          string `json:"http.referer"`
		TransferEncoding string `json:"http.transfer_encoding"`
		Origin           string `json:"http.origin"`
	}

	var tmp tmpHttp
	jsonData, err := sonic.Marshal(src)
	if err != nil {
		return nil, errors.Wrapf(err, "HTTP: %s", ErrParseFrame)
	}

	err = sonic.Unmarshal(jsonData, &tmp)
	if err != nil {
		return nil, errors.Wrapf(err, "HTTP: %s", ErrParseFrame)
	}

	// dynamic key like: "HTTP/1.1 404 Not Found\\r\\n"
	for key, value := range src {
		if strings.HasPrefix(key, "HTTP/") {
			if nested, ok := value.(map[string]any); ok {
				if version, ok := nested["http.response.version"].(string); ok {
					tmp.ResponseVersion = version
				}
				if code, ok := nested["http.response.code"].(string); ok {
					tmp.ResponseCode = code
				}
				if desc, ok := nested["http.response.code.desc"].(string); ok {
					tmp.ResponseCodeDesc = desc
				}
				if phrase, ok := nested["http.response.phrase"].(string); ok {
					tmp.ResponsePhrase = phrase
				}
			}
		}
	}

	reqLine, err := parseFieldAsArray(tmp.RequestLine)
	if err != nil {
		return nil, errors.Wrapf(err, "HTTP: %s", "fail to parse RequestLine")
	}

	respLine, err := parseFieldAsArray(tmp.ResponseLine)
	if err != nil {
		return nil, errors.Wrapf(err, "HTTP: %s", "fail to parse ResponseLine")
	}

	return &Http{
		Date:                tmp.Date,
		Host:                tmp.Host,
		UserAgent:           tmp.UserAgent,
		Accept:              tmp.Accept,
		LastModified:        tmp.LastModified,
		ContentType:         tmp.ContentType,
		ContentLengthHeader: tmp.ContentLengthHeader,
		ContentLength:       tmp.ContentLength,
		FileData:            tmp.FileData,
		Server:              tmp.Server,
		Time:                tmp.Time,

		Request:        tmp.Request,
		RequestLine:    reqLine,
		RequestIn:      tmp.RequestIn,
		RequestUri:     tmp.RequestUri,
		RequestFullUri: tmp.RequestFullUri,

		Response:         tmp.Response,
		ResponseVersion:  tmp.ResponseVersion,
		ResponseCode:     tmp.ResponseCode,
		ResponseCodeDesc: tmp.ResponseCodeDesc,
		ResponsePhrase:   tmp.ResponsePhrase,
		ResponseLine:     respLine,
		ResponseUrl:      tmp.ResponseUrl,
		ResponseNumber:   tmp.ResponseNumber,

		Connection:       tmp.Connection,
		CacheControl:     tmp.CacheControl,
		Cookie:           tmp.Cookie,
		AcceptEncoding:   tmp.AcceptEncoding,
		AcceptLanguage:   tmp.AcceptLanguage,
		Referer:          tmp.Referer,
		TransferEncoding: tmp.TransferEncoding,
		Origin:           tmp.Origin,
	}, nil
}

func parseMultipleHttp(src []any) ([]*Http, error) {
	var httpLayers []*Http
	for _, item := range src {
		itemMap, ok := item.(map[string]any)
		if !ok {
			return nil, errors.Wrapf(ErrParseFrame, "HTTP: unexpected type %T in array", item)
		}

		http, err := parseSingleHttp(itemMap)
		if err != nil {
			return nil, err
		}
		httpLayers = append(httpLayers, http)
	}
	return httpLayers, nil
}

type DnsFlags struct {
	Response           bool `json:"dns.flags.response"`
	Authoritative      bool `json:"dns.flags.authoritative"`
	Truncated          bool `json:"dns.flags.truncated"`
	RecursionDesired   bool `json:"dns.flags.rd"`
	RecursionAvailable bool `json:"dns.flags.ra"`
}

// Dns wireshark frame.dns
type Dns struct {
	DnsID        string      `json:"dns.id"`
	Flags        string      `json:"dns.flags"`
	QueriesCount int         `json:"dns.count.queries"`
	Queries      []DnsQuery  `json:"Queries"`
	AnswersCount int         `json:"dns.count.answers"`
	Answers      []DnsAnswer `json:"Answers"`
}

type DnsQuery struct {
	DnsQryName     string `json:"dns.qry.name"`
	DnsQryNameLen  string `json:"dns.qry.name.len"`
	DnsCountLabels string `json:"dns.count.labels"`
	DnsQryType     string `json:"dns.qry.type"`
	DnsQryClass    string `json:"dns.qry.class"`
}

type DnsAnswer struct {
	DnsA         string `json:"dns.a"`
	DnsRespName  string `json:"dns.resp.name"`
	DnsRespType  string `json:"dns.resp.type"`
	DnsRespClass string `json:"dns.resp.class"`
	DnsRespTtl   string `json:"dns.resp.ttl"`
	DnsRespLen   string `json:"dns.resp.len"`
}

func (l Layers) Dns() (dns any, err error) {
	src, ok := l["dns"]
	if !ok {
		return nil, errors.Wrap(ErrLayerNotFound, "dns")
	}

	type tmpDns struct {
		DnsID        string `json:"dns.id"`
		Flags        string `json:"dns.flags"`
		QueriesCount string `json:"dns.count.queries"`
		Queries      any    `json:"Queries"`
		AnswersCount string `json:"dns.count.answers"`
		Answers      any    `json:"Answers"`
	}
	var tmp tmpDns

	jsonData, err := sonic.Marshal(src)
	if err != nil {
		return nil, errors.Wrapf(err, "DNS: %s", ErrParseFrame)
	}

	err = sonic.Unmarshal(jsonData, &tmp)
	if err != nil {
		return nil, errors.Wrapf(err, "DNS: %s", ErrParseFrame)
	}

	queriesCount, _ := strconv.Atoi(tmp.QueriesCount)
	queries := make([]DnsQuery, queriesCount)
	if m, ok := tmp.Queries.(map[string]any); ok {
		if len(m) == 0 {
			return
		}

		mCount := 0
		for _, v := range m {
			var queryTmp DnsQuery
			jsonBytes, _ := sonic.Marshal(v)
			_ = sonic.Unmarshal(jsonBytes, &queryTmp)
			queries[mCount] = queryTmp
			mCount++
		}
	}

	answersCount, _ := strconv.Atoi(tmp.AnswersCount)
	answers := make([]DnsAnswer, answersCount)
	if m, ok := tmp.Answers.(map[string]any); ok {
		if len(m) == 0 {
			return
		}

		mCount := 0
		for _, v := range m {
			var answerTmp DnsAnswer
			jsonBytes, _ := sonic.Marshal(v)
			_ = sonic.Unmarshal(jsonBytes, &answerTmp)
			answers[mCount] = answerTmp
			mCount++
		}
	}

	return &Dns{
		DnsID:        tmp.DnsID,
		Flags:        tmp.Flags,
		QueriesCount: queriesCount,
		Queries:      queries,
		AnswersCount: answersCount,
		Answers:      answers,
	}, nil
}
