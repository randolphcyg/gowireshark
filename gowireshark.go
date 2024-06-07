package gowireshark

/*
#cgo pkg-config: glib-2.0
#cgo LDFLAGS: -Wl,-rpath,${SRCDIR}/libs
#cgo LDFLAGS: -L${SRCDIR}/libs -lwiretap -lwsutil -lwireshark -lpcap
#cgo CFLAGS: -I${SRCDIR}/include
#cgo CFLAGS: -I${SRCDIR}/include/wireshark
#cgo CFLAGS: -I${SRCDIR}/include/libpcap

#include "lib.h"
#include "online.h"
#include "offline.h"
*/
import "C"
import (
	"encoding/json"
	"log/slog"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/pkg/errors"
)

var (
	ErrFileNotFound           = errors.New("cannot open file, no such file")
	ErrReadFile               = errors.New("occur error when read file ")
	ErrIllegalPara            = errors.New("illegal parameter")
	WarnFrameIndexOutOfBounds = errors.New("frame index is out of bounds")
	ErrUnmarshalObj           = errors.New("unmarshal obj error")
	ErrFromCLogic             = errors.New("run c logic occur error")
	ErrParseDissectRes        = errors.New("fail to parse DissectRes")
	ErrParseFrame             = errors.New("fail to parse frame")
	ErrFrameIsBlank           = errors.New("frame data is blank")
)

// DissectResChans dissect result chan map
var DissectResChans = make(map[string]chan FrameDissectRes)

var EpanMutex = &sync.Mutex{}

// Init policies、WTAP mod、EPAN mod.
func init() {
	initEnvRes := C.init_env()
	if initEnvRes == 0 {
		panic("fail to init env")
	}
}

// isFileExist check if the file path exists
func isFileExist(path string) bool {
	_, err := os.Lstat(path)
	return !os.IsNotExist(err)
}

// CChar2GoStr C string -> Go string
func CChar2GoStr(src *C.char) string {
	return C.GoStringN(src, C.int(C.strlen(src)))
}

// EpanVersion get epan module's version
func EpanVersion() string {
	return C.GoString((*C.char)(C.epan_get_version()))
}

// EpanPluginsSupported
//
//	@Description:
//	@return int: 0 if plugins can be loaded for all of libwireshark (tap, dissector, epan);
//	1 if plugins are not supported by the platform;
//	-1 if plugins were disabled in the build configuration.
func EpanPluginsSupported() int {
	return int(C.epan_plugins_supported())
}

// initCapFile Init capture file only once for each pcap file
func initCapFile(inputFilepath string) (err error) {
	if !isFileExist(inputFilepath) {
		err = errors.Wrap(ErrFileNotFound, inputFilepath)
		return
	}

	inputFilepathCStr := C.CString(inputFilepath)
	errNo := C.init_cf(inputFilepathCStr)
	if errNo != 0 {
		err = errors.Wrap(ErrReadFile, strconv.Itoa(int(errNo)))
		return
	}

	return
}

// DissectPrintFirstFrame Dissect and print the first frame
func DissectPrintFirstFrame(inputFilepath string) (err error) {
	EpanMutex.Lock()
	defer EpanMutex.Unlock()

	err = initCapFile(inputFilepath)
	if err != nil {
		return
	}

	C.print_first_frame()

	return
}

// DissectPrintAllFrame Dissect and print all frames
func DissectPrintAllFrame(inputFilepath string) (err error) {
	EpanMutex.Lock()
	defer EpanMutex.Unlock()

	err = initCapFile(inputFilepath)
	if err != nil {
		return
	}

	C.print_all_frame()

	return
}

// DissectPrintFirstSeveralFrame
//
//	@Description: Dissect and print the first several frames
//	@param inputFilepath: Pcap src file path
//	@param count: The index of the first several frame you want to dissect
func DissectPrintFirstSeveralFrame(inputFilepath string, count int) (err error) {
	EpanMutex.Lock()
	defer EpanMutex.Unlock()

	err = initCapFile(inputFilepath)
	if err != nil {
		return
	}

	if count < 1 {
		err = errors.Wrap(ErrIllegalPara, strconv.Itoa(count))
		return
	}

	C.print_first_several_frame(C.int(count))

	return
}

// DissectPrintSpecificFrame
//
//	@Description: Dissect and print the Specific frame
//	@param inputFilepath: Pcap src file path
//	@param num: The index value of the specific frame you want to dissect
func DissectPrintSpecificFrame(inputFilepath string, num int) (err error) {
	EpanMutex.Lock()
	defer EpanMutex.Unlock()

	err = initCapFile(inputFilepath)
	if err != nil {
		return
	}

	if num < 1 {
		err = errors.Wrap(ErrIllegalPara, "Frame num "+strconv.Itoa(num))
		return
	}

	// errNo is 2 if num is out of bounds
	errNo := C.print_specific_frame(C.int(num))
	if errNo == 2 {
		err = errors.Wrap(WarnFrameIndexOutOfBounds, strconv.Itoa(int(errNo)))
		return
	}

	return
}

// HexData hex data
type HexData struct {
	Offset []string `json:"offset"`
	Hex    []string `json:"hex"`
	Ascii  []string `json:"ascii"`
}

// UnmarshalHexData Unmarshal hex data dissect result
func UnmarshalHexData(src string) (res HexData, err error) {
	err = json.Unmarshal([]byte(src), &res)
	if err != nil {
		return HexData{}, err
	}

	return
}

// GetSpecificFrameHexData Get hex data of specific frame
func GetSpecificFrameHexData(inputFilepath string, num int) (hexData HexData, err error) {
	EpanMutex.Lock()
	defer EpanMutex.Unlock()

	err = initCapFile(inputFilepath)
	if err != nil {
		return
	}

	// get specific frame hex data in json format by c
	srcHex := C.get_specific_frame_hex_data(C.int(num))
	if srcHex != nil {
		if C.strlen(srcHex) == 0 { // loop ends
			return
		}
	}

	// unmarshal dissect result
	hexData, err = UnmarshalHexData(CChar2GoStr(srcHex))
	if err != nil {
		err = errors.Wrap(ErrUnmarshalObj, "Frame num "+strconv.Itoa(num))
		return
	}

	return
}

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
	FileData            string   `json:"http.file_data"`
	Response            string   `json:"http.response"`
}

func UnmarshalHttp(src any) (http Http, err error) {
	type tmpHttp struct {
		Date                string   `json:"http.date"`
		ResponseLine        []string `json:"http.response.line"`
		LastModified        string   `json:"http.last_modified"`
		ResponseNumber      string   `json:"http.response_number"`
		ContentType         string   `json:"http.content_type"`
		ContentLengthHeader string   `json:"http.content_length_header"`
		FileData            string   `json:"http.file_data"`
		Response            string   `json:"http.response"`
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
		FileData:            tmp.FileData,
		Response:            tmp.Response,
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

// UnmarshalDissectResult Unmarshal dissect result
func UnmarshalDissectResult(src string) (res FrameDissectRes, err error) {
	err = json.Unmarshal([]byte(src), &res)
	if err != nil {
		return FrameDissectRes{}, ErrParseDissectRes
	}

	return
}

// GetSpecificFrameProtoTreeInJson
//
//	@Description: Transfer specific frame proto tree to json format
//	@param inputFilepath: Pcap src file path
//	@param num: The max frame index value of the JSON results
//	@param isDescriptive: Whether the JSON result has descriptive fields
//	@param isDebug: Whether to print JSON result in C logic
//	@return res: Contains specific frame's JSON dissect result
func GetSpecificFrameProtoTreeInJson(inputFilepath string, num int, isDescriptive, isDebug bool) (frameDissectRes FrameDissectRes, err error) {
	EpanMutex.Lock()
	defer EpanMutex.Unlock()

	err = initCapFile(inputFilepath)
	if err != nil {
		return
	}

	descriptive := 0
	if isDescriptive {
		descriptive = 1
	}

	debug := 0
	if isDebug {
		debug = 1
	}

	counter := 0
	for {
		counter++
		if counter < num && num != counter {
			continue
		}

		// get proto dissect result in json format by c
		srcFrame := C.proto_tree_in_json(C.int(counter), C.int(descriptive), C.int(debug))
		if srcFrame != nil {
			if C.strlen(srcFrame) == 0 {
				return frameDissectRes, ErrFrameIsBlank
			}
		}

		// unmarshal dissect result
		frameDissectRes, err = UnmarshalDissectResult(CChar2GoStr(srcFrame))
		if err != nil {
			err = errors.Wrap(ErrUnmarshalObj, "Counter "+strconv.Itoa(counter))
			return
		}

		return
	}
}

// GetAllFrameProtoTreeInJson
//
//	@Description: Transfer proto tree to json format
//	@param inputFilepath: Pcap src file path
//	@param isDescriptive: Whether the JSON result has descriptive fields
//	@param isDebug: Whether to print JSON result in C logic
//	@return res: Contains all frame's JSON dissect result
func GetAllFrameProtoTreeInJson(inputFilepath string, isDescriptive bool, isDebug bool) (res []FrameDissectRes, err error) {
	EpanMutex.Lock()
	defer EpanMutex.Unlock()

	err = initCapFile(inputFilepath)
	if err != nil {
		return
	}

	descriptive := 0
	if isDescriptive {
		descriptive = 1
	}

	debug := 0
	if isDebug {
		debug = 1
	}

	counter := 1
	for {
		// get proto dissect result in json format by c
		srcFrame := C.proto_tree_in_json(C.int(counter), C.int(descriptive), C.int(debug))
		if srcFrame != nil {
			if C.strlen(srcFrame) == 0 { // loop ends
				break
			}
		}

		// unmarshal dissect result
		singleFrame, err := UnmarshalDissectResult(CChar2GoStr(srcFrame))
		if err != nil {
			err = errors.Wrap(ErrUnmarshalObj, "Counter "+strconv.Itoa(counter))
			slog.Warn(err.Error())
		}

		res = append(res, singleFrame)
		counter++
	}

	return
}

// IFace interface device
type IFace struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Flags       int    `json:"flags"`
}

// UnmarshalIFace Unmarshal interface device
func UnmarshalIFace(src string) (res map[string]IFace, err error) {
	err = json.Unmarshal([]byte(src), &res)
	if err != nil {
		return nil, err
	}

	return
}

// GetIfaceList Get interface list
func GetIfaceList() (res map[string]IFace, err error) {
	// unmarshal interface device list obj
	res, err = UnmarshalIFace(CChar2GoStr(C.get_if_list()))
	if err != nil {
		err = ErrUnmarshalObj
		return
	}

	return
}

// GetIfaceNonblockStatus Get interface nonblock status
func GetIfaceNonblockStatus(deviceName string) (isNonblock bool, err error) {
	if deviceName == "" {
		err = errors.Wrap(err, "device name is blank")
		return
	}

	nonblockStatus := C.get_if_nonblock_status(C.CString(deviceName))
	if nonblockStatus == 0 {
		isNonblock = false
	} else if nonblockStatus == 1 {
		isNonblock = true
	} else {
		err = errors.Wrapf(ErrFromCLogic, "nonblockStatus:%v", nonblockStatus)
	}

	return
}

// SetIfaceNonblockStatus Set interface nonblock status
func SetIfaceNonblockStatus(deviceName string, isNonblock bool) (status bool, err error) {
	if deviceName == "" {
		err = errors.Wrap(err, "device name is blank")
		return
	}

	setNonblockCode := 0
	if isNonblock {
		setNonblockCode = 1
	}

	nonblockStatus := C.set_if_nonblock_status(C.CString(deviceName), C.int(setNonblockCode))
	if nonblockStatus == 0 {
		status = false
	} else if nonblockStatus == 1 {
		status = true
	} else {
		err = errors.Wrapf(ErrFromCLogic, "nonblockStatus:%v", nonblockStatus)
	}

	return
}

//export GoDataCallback
func GoDataCallback(data *C.char, length C.int, deviceName *C.char) {
	goPacket := ""
	if data != nil {
		goPacket = C.GoStringN(data, length)
	}

	deviceNameStr := ""
	if deviceName != nil {
		deviceNameStr = C.GoString(deviceName)
	}

	// unmarshal each pkg dissect result
	singleFrameData, err := UnmarshalDissectResult(goPacket)
	if err != nil {
		err = errors.Wrap(ErrUnmarshalObj, "WsIndex: "+singleFrameData.WsIndex)
		slog.Warn(err.Error())
	}

	// write packet dissect result to go pipe
	if ch, ok := DissectResChans[deviceNameStr]; ok {
		ch <- singleFrameData
	}
}

// DissectPktLive
//
//	@Description: Set up callback function, capture and dissect packet.
//	@param deviceName
//	@param bpfFilter bpf filter
//	@param num
//	@param promisc: 0 indicates a non-promiscuous mode, and any other value indicates a promiscuous mode
//	@param timeout
func DissectPktLive(deviceName, bpfFilter string, num, promisc, timeout int) (err error) {
	// Set up callback function
	C.setDataCallback((C.DataCallback)(C.GoDataCallback))

	if deviceName == "" {
		err = errors.Wrap(err, "device name is blank")
		return
	}

	errMsg := C.handle_packet(C.CString(deviceName), C.CString(bpfFilter), C.int(num), C.int(promisc), C.int(timeout))
	if C.strlen(errMsg) != 0 {
		// transfer c char to go string
		errMsgStr := CChar2GoStr(errMsg)
		err = errors.Errorf("fail to capture packet live:%s", errMsgStr)
		return
	}

	return
}

// StopDissectPktLive Stop capture packet live、 free all memory allocated.
func StopDissectPktLive(deviceName string) (err error) {
	if deviceName == "" {
		err = errors.Wrap(err, "device name is blank")
		return
	}

	errMsg := C.stop_dissect_capture_pkg(C.CString(deviceName))
	if C.strlen(errMsg) != 0 {
		// transfer c char to go string
		errMsgStr := CChar2GoStr(errMsg)
		err = errors.Errorf("fail to stop capture packet live:%s", errMsgStr)
		return
	}

	return
}

// TimeEpoch2Time turn wireshark timestamp to time.Time
func TimeEpoch2Time(wiresharkTimestamp float64) (goTime time.Time) {
	seconds := int64(wiresharkTimestamp)
	microseconds := int64((wiresharkTimestamp - float64(seconds)) * 1e6)
	return time.Unix(seconds, microseconds*1000)
}
