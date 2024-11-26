package gowireshark

import (
	"encoding/json"
	"strconv"
)

// FrameDissectRes Dissect results of each frame of data
type FrameDissectRes struct {
	WsIndex  string   `json:"_index"`
	Offset   []string `json:"offset"`
	Hex      []string `json:"hex"`
	Ascii    []string `json:"ascii"`
	WsSource struct {
		Layers map[string]any `json:"layers"`
	} `json:"_source"`
}

// Frame wireshark frame
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
}

func UnmarshalFrame(src any) (frame Frame, err error) {
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
	}
	var tmp tmpFrame

	jsonData, err := json.Marshal(src)
	if err != nil {
		return
	}

	err = json.Unmarshal(jsonData, &tmp)
	if err != nil {
		return
	}

	sectionNumber, _ := strconv.Atoi(tmp.SectionNumber)
	interfaceID, _ := strconv.Atoi(tmp.InterfaceID)
	num, _ := strconv.Atoi(tmp.Number)
	length, _ := strconv.Atoi(tmp.Len)
	capLen, _ := strconv.Atoi(tmp.CapLen)
	marked, err := strconv.ParseBool(tmp.Marked)
	if err != nil {
		return
	}
	ignored, err := strconv.ParseBool(tmp.Ignored)
	if err != nil {
		return
	}
	timeEpoch, err := strconv.ParseFloat(tmp.TimeEpoch, 64)

	return Frame{
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
		Len:                length,
		CapLen:             capLen,
		Marked:             marked,
		Ignored:            ignored,
		Protocols:          tmp.Protocols,
	}, nil
}

// WsCol wireshark frame._ws.col
type WsCol struct {
	Num       int    `json:"_ws.col.number"`
	DefSrc    string `json:"_ws.col.def_src"`
	DefDst    string `json:"_ws.col.def_dst"`
	Protocol  string `json:"_ws.col.protocol"`
	PacketLen int    `json:"_ws.col.packet_length"`
	Info      string `json:"_ws.col.info"`
}

func UnmarshalWsCol(src any) (wsCol WsCol, err error) {
	type tmpWsCol struct {
		Num       string `json:"_ws.col.number"`
		DefSrc    string `json:"_ws.col.def_src"`
		DefDst    string `json:"_ws.col.def_dst"`
		Protocol  string `json:"_ws.col.protocol"`
		PacketLen string `json:"_ws.col.packet_length"`
		Info      string `json:"_ws.col.info"`
	}
	var tmp tmpWsCol

	jsonData, err := json.Marshal(src)
	if err != nil {
		return
	}

	err = json.Unmarshal(jsonData, &tmp)
	if err != nil {
		return WsCol{}, ErrParseFrame
	}

	num, _ := strconv.Atoi(tmp.Num)
	packetLen, _ := strconv.Atoi(tmp.PacketLen)

	return WsCol{
		Num:       num,
		DefSrc:    tmp.DefSrc,
		DefDst:    tmp.DefDst,
		Protocol:  tmp.Protocol,
		PacketLen: packetLen,
		Info:      tmp.Info,
	}, nil
}

// Ip wireshark frame.ip
type Ip struct {
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
}

func UnmarshalIp(src any) (ip Ip, err error) {
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
	}
	var tmp tmpIp

	jsonData, err := json.Marshal(src)
	if err != nil {
		return
	}

	err = json.Unmarshal(jsonData, &tmp)
	if err != nil {
		return Ip{}, ErrParseFrame
	}

	hdrLen, _ := strconv.Atoi(tmp.HdrLen)
	length, _ := strconv.Atoi(tmp.Len)
	fragOffset, _ := strconv.Atoi(tmp.FragOffset)
	ttl, _ := strconv.Atoi(tmp.Ttl)
	version, _ := strconv.Atoi(tmp.Version)

	return Ip{
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
	}, nil
}

// Udp wireshark frame.udp
type Udp struct {
	SrcPort        int    `json:"udp.srcport"`
	DstPort        int    `json:"udp.dstport"`
	Length         int    `json:"udp.length"`
	ChecksumStatus string `json:"udp.checksum.status"`
	Port           []int  `json:"udp.port"`
	Checksum       string `json:"udp.checksum"`
	Stream         int    `json:"udp.stream"`
}

func UnmarshalUdp(src any) (udp Udp, err error) {
	type tmpUdp struct {
		SrcPort        string   `json:"udp.srcport"`
		DstPort        string   `json:"udp.dstport"`
		Length         string   `json:"udp.length"`
		ChecksumStatus string   `json:"udp.checksum.status"`
		Port           []string `json:"udp.port"`
		Checksum       string   `json:"udp.checksum"`
		Stream         string   `json:"udp.stream"`
	}
	var tmp tmpUdp

	jsonData, err := json.Marshal(src)
	if err != nil {
		return
	}

	err = json.Unmarshal(jsonData, &tmp)
	if err != nil {
		return Udp{}, ErrParseFrame
	}

	srcPort, _ := strconv.Atoi(tmp.SrcPort)
	stream, _ := strconv.Atoi(tmp.Stream)
	length, _ := strconv.Atoi(tmp.Length)
	dstPort, _ := strconv.Atoi(tmp.DstPort)
	var ports []int
	for _, p := range tmp.Port {
		pTmp, _ := strconv.Atoi(p)
		ports = append(ports, pTmp)
	}

	return Udp{
		SrcPort:        srcPort,
		Length:         length,
		ChecksumStatus: tmp.ChecksumStatus,
		DstPort:        dstPort,
		Port:           ports,
		Checksum:       tmp.Checksum,
		Stream:         stream,
	}, nil
}

// Tcp wireshark frame.tcp
type Tcp struct {
	HdrLen         int    `json:"tcp.hdr_len"`
	SrcPort        int    `json:"tcp.srcport"`
	DstPort        int    `json:"tcp.dstport"`
	Len            int    `json:"tcp.len"`
	ChecksumStatus string `json:"tcp.checksum.status"`
	Port           []int  `json:"tcp.port"`
	Checksum       string `json:"tcp.checksum"`
	Stream         int    `json:"tcp.stream"`
	SeqRaw         int    `json:"tcp.seq_raw"`
	AckRaw         int    `json:"tcp.ack_raw"`
	Payload        string `json:"tcp.payload"`
}

func UnmarshalTcp(src any) (tcp Tcp, err error) {
	type tmpTcp struct {
		HdrLen         string   `json:"tcp.hdr_len"`
		SrcPort        string   `json:"tcp.srcport"`
		DstPort        string   `json:"tcp.dstport"`
		Len            string   `json:"tcp.len"`
		ChecksumStatus string   `json:"tcp.checksum.status"`
		Port           []string `json:"tcp.port"`
		Checksum       string   `json:"tcp.checksum"`
		Stream         string   `json:"tcp.stream"`
		SeqRaw         string   `json:"tcp.seq_raw"`
		AckRaw         string   `json:"tcp.ack_raw"`
		Payload        string   `json:"tcp.payload"`
	}
	var tmp tmpTcp

	jsonData, err := json.Marshal(src)
	if err != nil {
		return
	}

	err = json.Unmarshal(jsonData, &tmp)
	if err != nil {
		return Tcp{}, ErrParseFrame
	}

	hdrLen, _ := strconv.Atoi(tmp.HdrLen)
	srcPort, _ := strconv.Atoi(tmp.SrcPort)
	stream, _ := strconv.Atoi(tmp.Stream)
	length, _ := strconv.Atoi(tmp.Len)
	dstPort, _ := strconv.Atoi(tmp.DstPort)
	seqRaw, _ := strconv.Atoi(tmp.SeqRaw)
	ackRaw, _ := strconv.Atoi(tmp.AckRaw)
	var ports []int
	for _, p := range tmp.Port {
		pTmp, _ := strconv.Atoi(p)
		ports = append(ports, pTmp)
	}

	return Tcp{
		HdrLen:         hdrLen,
		SrcPort:        srcPort,
		DstPort:        dstPort,
		Len:            length,
		ChecksumStatus: tmp.ChecksumStatus,
		Port:           ports,
		Checksum:       tmp.Checksum,
		Stream:         stream,
		SeqRaw:         seqRaw,
		AckRaw:         ackRaw,
		Payload:        tmp.Payload,
	}, nil
}

// Http wireshark frame.http
type Http struct {
	Date                string   `json:"http.date"`
	ResponseLine        []string `json:"http.response.line"`
	LastModified        string   `json:"http.last_modified"`
	ResponseNumber      string   `json:"http.response_number"`
	ContentType         string   `json:"http.content_type"`
	ContentLengthHeader string   `json:"http.content_length_header"`
	ContentLength       string   `json:"http.content_length"`
	FileData            string   `json:"http.file_data"`
	Response            string   `json:"http.response"`
	ResponseVersion     string   `json:"http.response.version"`
	ResponseCode        string   `json:"http.response.code"`
	ResponseCodeDesc    string   `json:"http.response.code.desc"`
	ResponsePhrase      string   `json:"http.response.phrase"`
	RequestIn           string   `json:"http.request_in"`
	RequestUri          string   `json:"http.request.uri"`
	RequestFullUri      string   `json:"http.request.full_uri"`
	Server              string   `json:"http.server"`
	Time                string   `json:"http.time"`
}

func UnmarshalHttp(src any) (http Http, err error) {
	type tmpHttp struct {
		Date                string   `json:"http.date"`
		ResponseLine        []string `json:"http.response.line"`
		LastModified        string   `json:"http.last_modified"`
		ResponseNumber      string   `json:"http.response_number"`
		ContentType         string   `json:"http.content_type"`
		ContentLengthHeader string   `json:"http.content_length_header"`
		ContentLength       string   `json:"http.content_length"`
		FileData            string   `json:"http.file_data"`
		Response            string   `json:"http.response"`
		ResponseVersion     string   `json:"http.response.version"`
		ResponseCode        string   `json:"http.response.code"`
		ResponseCodeDesc    string   `json:"http.response.code.desc"`
		ResponsePhrase      string   `json:"http.response.phrase"`
		RequestIn           string   `json:"http.request_in"`
		RequestUri          string   `json:"http.request.uri"`
		RequestFullUri      string   `json:"http.request.full_uri"`
		Server              string   `json:"http.server"`
		Time                string   `json:"http.time"`
	}
	var tmp tmpHttp

	jsonData, err := json.Marshal(src)
	if err != nil {
		return
	}

	err = json.Unmarshal(jsonData, &tmp)
	if err != nil {
		return Http{}, ErrParseFrame
	}

	return Http{
		Date:                tmp.Date,
		ResponseLine:        tmp.ResponseLine,
		LastModified:        tmp.LastModified,
		ResponseNumber:      tmp.ResponseNumber,
		ContentType:         tmp.ContentType,
		ContentLengthHeader: tmp.ContentLengthHeader,
		ContentLength:       tmp.ContentLength,
		FileData:            tmp.FileData,
		Response:            tmp.Response,
		ResponseVersion:     tmp.ResponseVersion,
		ResponseCode:        tmp.ResponseCode,
		ResponseCodeDesc:    tmp.ResponseCodeDesc,
		ResponsePhrase:      tmp.ResponsePhrase,
		RequestIn:           tmp.RequestIn,
		RequestUri:          tmp.RequestUri,
		RequestFullUri:      tmp.RequestFullUri,
		Server:              tmp.Server,
		Time:                tmp.Time,
	}, nil
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

func UnmarshalDns(src any) (dns Dns, err error) {
	type tmpDns struct {
		DnsID        string `json:"dns.id"`
		Flags        string `json:"dns.flags"`
		QueriesCount string `json:"dns.count.queries"`
		Queries      any    `json:"Queries"`
		AnswersCount string `json:"dns.count.answers"`
		Answers      any    `json:"Answers"`
	}
	var tmp tmpDns

	jsonData, err := json.Marshal(src)
	if err != nil {
		return
	}

	err = json.Unmarshal(jsonData, &tmp)
	if err != nil {
		return Dns{}, ErrParseFrame
	}

	queriesCount, _ := strconv.Atoi(tmp.QueriesCount)
	queries := make([]DnsQuery, queriesCount)
	if m, ok := tmp.Queries.(map[string]interface{}); ok {
		if len(m) == 0 {
			return
		}

		mCount := 0
		for _, v := range m {
			var queryTmp DnsQuery
			jsonBytes, _ := json.Marshal(v)
			_ = json.Unmarshal(jsonBytes, &queryTmp)
			queries[mCount] = queryTmp
			mCount++
		}
	}

	answersCount, _ := strconv.Atoi(tmp.AnswersCount)
	answers := make([]DnsAnswer, answersCount)
	if m, ok := tmp.Answers.(map[string]interface{}); ok {
		if len(m) == 0 {
			return
		}

		mCount := 0
		for _, v := range m {
			var answerTmp DnsAnswer
			jsonBytes, _ := json.Marshal(v)
			_ = json.Unmarshal(jsonBytes, &answerTmp)
			answers[mCount] = answerTmp
			mCount++
		}
	}

	return Dns{
		DnsID:        tmp.DnsID,
		Flags:        tmp.Flags,
		QueriesCount: queriesCount,
		Queries:      queries,
		AnswersCount: answersCount,
		Answers:      answers,
	}, nil
}
