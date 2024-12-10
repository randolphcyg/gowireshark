package gowireshark

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pkg/errors"
)

const inputFilepath = "./pcaps/mysql.pcapng"

func TestEpanVersion(t *testing.T) {
	t.Log(EpanVersion())
}

func TestEpanPluginsSupported(t *testing.T) {
	t.Logf("expected 0, got %d", EpanPluginsSupported())
}

func TestDissectPrintAllFrame(t *testing.T) {
	err := DissectPrintAllFrame(inputFilepath)
	if err != nil {
		t.Fatal(err)
	}
}

func TestGetSpecificFrameHexData(t *testing.T) {
	res, err := GetSpecificFrameHexData(inputFilepath, 65)
	if err != nil {
		t.Fatal(err)
	}

	for i, item := range res.Offset {
		t.Log(i, item)
	}
	for i, item := range res.Hex {
		t.Log(i, item)
	}
	for i, item := range res.Ascii {
		t.Log(i, item)
	}
}

func TestGetSpecificFrameProtoTreeInJson(t *testing.T) {
	frameData, err := GetSpecificFrameProtoTreeInJson(inputFilepath, 65,
		WithDescriptive(true), WithDebug(true))
	if err != nil {
		t.Fatal(err)
	}

	t.Log("# Frame index:", frameData.BaseLayers.Frame.Number, "===========================")
	t.Log("【layer _ws.col.protocol】:", frameData.BaseLayers.WsCol.Protocol)

	if frameData.BaseLayers.Ip != nil {
		t.Log("## ip.src:", frameData.BaseLayers.Ip.Src)
		t.Log("## ip.dst:", frameData.BaseLayers.Ip.Dst)
	}

	t.Log("@@@", frameData.WsSource.Layers[strings.ToLower(frameData.BaseLayers.WsCol.Protocol)])

}

/*
DEMO: parse custom protocol
*/
type MySQLCapsTree struct {
	CD string `json:"mysql.caps.cd"` // Capability: CLIENT_DEPRECATED
	CP string `json:"mysql.caps.cp"` // Capability: CLIENT_PROTOCOL
	CU string `json:"mysql.caps.cu"` // Capability: CLIENT_USER
	FR string `json:"mysql.caps.fr"` // Capability: CLIENT_FOUND_ROWS
	IA string `json:"mysql.caps.ia"` // Capability: CLIENT_IGNORE_SPACE
	II string `json:"mysql.caps.ii"` // Capability: CLIENT_INTERACTIVE
	IS string `json:"mysql.caps.is"` // Capability: CLIENT_IGNORE_SIGPIPE
	LF string `json:"mysql.caps.lf"` // Capability: CLIENT_LONG_FLAG
	LI string `json:"mysql.caps.li"` // Capability: CLIENT_LONG_PASSWORD
	LP string `json:"mysql.caps.lp"` // Capability: CLIENT_LOCAL_FILES
	NS string `json:"mysql.caps.ns"` // Capability: CLIENT_NO_SCHEMA
	OB string `json:"mysql.caps.ob"` // Capability: CLIENT_ODBC
	RS string `json:"mysql.caps.rs"` // Capability: CLIENT_RESERVED
	SC string `json:"mysql.caps.sc"` // Capability: CLIENT_SSL_COMPRESS
	SL string `json:"mysql.caps.sl"` // Capability: CLIENT_SSL
	TA string `json:"mysql.caps.ta"` // Capability: CLIENT_TRANSACTIONS
}

type MySQLExtCapsTree struct {
	CA               string `json:"mysql.caps.ca"`                // Extended Capability: CLIENT_AUTH
	CapExt           string `json:"mysql.caps.cap_ext"`           // Extended Capability
	CD               string `json:"mysql.caps.cd"`                // Extended Capability: CLIENT_DEPRECATED
	CompressZSD      string `json:"mysql.caps.compress_zsd"`      // Extended Capability
	DeprecateEOF     string `json:"mysql.caps.deprecate_eof"`     // Extended Capability: CLIENT_DEPRECATE_EOF
	EP               string `json:"mysql.caps.ep"`                // Extended Capability
	MFAuth           string `json:"mysql.caps.mf_auth"`           // Extended Capability: Multi-factor Authentication
	MR               string `json:"mysql.caps.mr"`                // Extended Capability: Multi-Resultsets
	MS               string `json:"mysql.caps.ms"`                // Extended Capability: Multi-Statements
	OptionalMetadata string `json:"mysql.caps.optional_metadata"` // Optional Metadata
	PA               string `json:"mysql.caps.pa"`                // Plugin Authentication
	PM               string `json:"mysql.caps.pm"`                // Prepares Metadata
	QueryAttrs       string `json:"mysql.caps.query_attrs"`       // Query Attributes
	SessionTrack     string `json:"mysql.caps.session_track"`     // Session Tracking
	Unused           string `json:"mysql.caps.unused"`            // Unused
	VC               string `json:"mysql.caps.vc"`                // Version Check
}

type MySQLLoginRequest struct {
	CapsClient        string           `json:"mysql.caps.client"`         // Client Capabilities
	CapsClientTree    MySQLCapsTree    `json:"mysql.caps.client_tree"`    // Client Capabilities Tree
	ExtCapsClient     string           `json:"mysql.extcaps.client"`      // Extended Capabilities
	ExtCapsClientTree MySQLExtCapsTree `json:"mysql.extcaps.client_tree"` // Extended Capabilities Tree
	MaxPacket         string           `json:"mysql.max_packet"`          // Maximum Packet Size
	Collation         string           `json:"mysql.collation"`           // Collation Setting
	User              string           `json:"mysql.user"`                // Username
	Password          string           `json:"mysql.passwd"`              // Encrypted Password
	Schema            string           `json:"mysql.schema"`              // Default Schema
	Unused            string           `json:"mysql.unused"`              // Unused Field
	ClientAuthPlugin  string           `json:"mysql.client_auth_plugin"`  // Authentication Plugin
}

type MySQLLayer struct {
	PacketLength string            `json:"mysql.packet_length"` // Length of the packet
	PacketNumber string            `json:"mysql.packet_number"` // Sequence number of the packet
	LoginRequest MySQLLoginRequest `json:"mysql.login_request"` // Login request details
}

// Parse implements the ProtocolParser interface for MySQL.
func (p *MySQLLayer) Parse(layers Layers) (any, error) {
	src, ok := layers["mysql"]
	if !ok {
		return nil, errors.Wrap(ErrLayerNotFound, "mysql")
	}

	jsonData, err := json.Marshal(src)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(jsonData, &p)
	if err != nil {
		return nil, ErrParseFrame
	}

	return p, nil
}

func TestParseCustomProtocol(t *testing.T) {
	frameData, err := GetSpecificFrameProtoTreeInJson(inputFilepath, 65,
		WithDescriptive(true), WithDebug(true))
	if err != nil {
		t.Fatal(err)
	}

	// init ParserRegistry
	registry := NewParserRegistry()
	// register MySQL protocol Parser
	registry.Register("mysql", &MySQLLayer{})

	parsedLayer, err := registry.ParseProtocol("mysql", frameData.WsSource.Layers)
	if err != nil {
		t.Error("Error parsing MySQL protocol:", err)
	}

	mysqlLayer, ok := parsedLayer.(*MySQLLayer)
	if !ok {
		t.Error("Error parsing MySQL protocol:", err)
	}

	t.Log("Parsed MySQL layer, mysql.passwd:", mysqlLayer.LoginRequest.Password)
}

func TestParseHttps(t *testing.T) {
	pcapPath := "./pcaps/https.pcapng"

	// set TLS config
	tls := TlsConf{
		DesegmentSslRecords:         true,
		DesegmentSslApplicationData: true,
		KeysList: []Key{
			{
				Ip:       "192.168.17.128",
				Port:     443,
				Protocol: "tls",
				KeyFile:  "./pcaps/https.key",
				Password: "",
			},
			{
				Ip:       "2.2.2.2",
				Protocol: "",
				KeyFile:  "./pcaps/https.key",
				Password: "",
			},
			{
				Ip:       "1.1.1.1",
				Port:     0,
				Protocol: "",
				KeyFile:  "./pcaps/testInvalid.key",
				Password: "test1",
			},
		},
	}
	t.Log(tls)

	frameData, err := GetSpecificFrameProtoTreeInJson(pcapPath, 14,
		WithTls(tls), WithDescriptive(true), WithDebug(true))
	if err != nil {
		t.Fatal(err)
	}

	t.Log("# Frame index:", frameData.BaseLayers.Frame.Number, "===========================")
	t.Log("【layer _ws.col.protocol】:", frameData.BaseLayers.WsCol.Protocol)

	if frameData.BaseLayers.Ip != nil {
		t.Log("## ip.src:", frameData.BaseLayers.Ip.Src)
		t.Log("## ip.dst:", frameData.BaseLayers.Ip.Dst)
	}
	if frameData.BaseLayers.Udp != nil {
		t.Log("## udp.srcport:", frameData.BaseLayers.Udp.SrcPort)
	}
	if frameData.BaseLayers.Tcp != nil {
		t.Log("## tcp.dstport:", frameData.BaseLayers.Tcp.DstPort)
	}
	if frameData.BaseLayers.Http != nil {
		t.Log("## http:", frameData.BaseLayers.Http)
		if frameData.BaseLayers.Http.ResponseLine != nil {
			for _, header := range *frameData.BaseLayers.Http.ResponseLine {
				t.Log("#### http.ResponseLine >>>", header)
			}
		}
	}

}

func TestGetSeveralFrameProtoTreeInJson(t *testing.T) {
	nums := []int{11, 5, 0, 1, -1, 13, 288}
	res, err := GetSeveralFrameProtoTreeInJson(inputFilepath, nums,
		WithDescriptive(true), WithDebug(false))
	if err != nil {
		t.Fatal(err)
	}

	// [1 5 11 13]
	for _, frameData := range res {
		t.Log("# Frame index:", frameData.BaseLayers.WsCol.Num, "===========================")
		t.Log("## WsIndex:", frameData.WsIndex)
		t.Log("## Offset:", frameData.Offset)
		t.Log("## Hex:", frameData.Hex)
		t.Log("## Ascii:", frameData.Ascii)
	}
}

func TestGetAllFrameProtoTreeInJson(t *testing.T) {
	res, err := GetAllFrameProtoTreeInJson(inputFilepath,
		WithDescriptive(true), WithDebug(false))
	if err != nil {
		t.Fatal(err)
	}

	for _, frameData := range res {
		t.Log("# Frame index:", frameData.BaseLayers.WsCol.Num, "===========================")
		t.Log("## Hex:", frameData.Hex)
		t.Log("## Ascii:", frameData.Ascii)

		if frameData.BaseLayers.Ip != nil {
			t.Log("## ip.src:", frameData.BaseLayers.Ip.Src)
			t.Log("## ip.dst:", frameData.BaseLayers.Ip.Dst)
		}
		if frameData.BaseLayers.Http != nil {
			t.Log("## http.request.uri:", frameData.BaseLayers.Http.RequestUri)
		}
		if frameData.BaseLayers.Dns != nil {
			t.Log("## dns:", frameData.BaseLayers.Dns)
		}
	}
}

func TestGoroutineGetAllFrameProtoTreeInJson(t *testing.T) {
	var wg sync.WaitGroup
	numGoroutines := 100

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			res, err := GetAllFrameProtoTreeInJson(inputFilepath, WithDescriptive(true), WithDebug(false))
			if err != nil {
				t.Error(err)
			}
			t.Log(i, inputFilepath, " >>>> ", len(res))
		}(i)
	}

	wg.Wait()
}

/*
Get interface device list, TODO but not return addresses of device (cause c logic error)
*/
func TestGetIfaceList(t *testing.T) {
	iFaces, err := GetIfaceList()
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range iFaces {
		t.Log(k, v.Description, v.Flags)
	}
}

/*
Get interface device nonblock status, default is false
*/
func TestGetIfaceNonblockStatus(t *testing.T) {
	ifaceName := "en7"
	status, err := GetIfaceNonblockStatus(ifaceName)
	if err != nil {
		t.Fatal(err)
	}

	if status != false {
		t.Errorf("expected status false, got %v", status)
	}
}

func TestSetIfaceNonblockStatus(t *testing.T) {
	ifaceName := "en7"
	status, err := SetIfaceNonblockStatus(ifaceName, true)
	if err != nil {
		t.Fatal(err)
	}

	if status != true {
		t.Errorf("expected status true, got %v", status)
	}
}

/*
Test infinite loop capturing and Dissecting packets、stop capturing and Dissecting.
Set the num parameter of the DissectPktLive function to -1
to process packets in an infinite loop.
Stop capturing and Dissecting after 2 seconds
*/
func TestDissectPktLiveInfiniteAndStopCapturePkg(t *testing.T) {
	ifName := "en7"
	filter := ""
	pktNum := -1
	promisc := 1
	timeout := 5

	// DissectResChans put pkg dissect result struct into go pipe
	DissectResChans[ifName] = make(chan FrameDissectRes, 100)
	defer close(DissectResChans[ifName])

	// user read unmarshal data from go channel
	go func() {
		for frameData := range DissectResChans[ifName] {
			t.Log("# Frame index:", frameData.BaseLayers.WsCol.Num, "===========================")
			t.Log("## Hex:", frameData.Hex)
			t.Log("## Ascii:", frameData.Ascii)

			if frameData.BaseLayers.Ip != nil {
				t.Log("## ip.src:", frameData.BaseLayers.Ip.Src)
				t.Log("## ip.dst:", frameData.BaseLayers.Ip.Dst)
			}
			if frameData.BaseLayers.Http != nil {
				t.Log("【layer http.request.uri】:", frameData.BaseLayers.Http.RequestUri)
			}
		}
	}()

	go func() {
		t.Log("Simulate manual stop real-time packet capture!")
		time.Sleep(time.Second * 5)
		err := StopDissectPktLive(ifName)
		if err != nil {
			t.Error(err)
			return
		}
		t.Log("############ stop capture successfully! ##############")
	}()

	// start c client, capture and dissect packet
	err := DissectPktLive(ifName, filter, pktNum, promisc, timeout)
	if err != nil {
		t.Fatal(err)
	}
}

/*
Set the num parameter of the DissectPktLive function to a specific num like 50
to process packets in a limited loop.
*/
func TestDissectPktLiveSpecificNum(t *testing.T) {
	ifName := "en7"
	filter := ""
	pktNum := 5
	promisc := 1
	timeout := 5

	var wg sync.WaitGroup
	defer wg.Wait()

	DissectResChans[ifName] = make(chan FrameDissectRes, 100)
	defer close(DissectResChans[ifName])

	wg.Add(1)

	go func() {
		defer wg.Done()
		for frameData := range DissectResChans[ifName] {
			t.Log("# Frame index:", frameData.BaseLayers.Frame.Number, "===========================")
			t.Log("【layer _ws.col.protocol】:", frameData.BaseLayers.WsCol.Protocol)

			if frameData.BaseLayers.Ip != nil {
				t.Log("## ip.src:", frameData.BaseLayers.Ip.Src)
				t.Log("## ip.dst:", frameData.BaseLayers.Ip.Dst)
			}
			if frameData.BaseLayers.Udp != nil {
				t.Log("## udp.srcport:", frameData.BaseLayers.Udp.SrcPort)
			}
			if frameData.BaseLayers.Tcp != nil {
				t.Log("## tcp.dstport:", frameData.BaseLayers.Tcp.DstPort)
			}
			if frameData.BaseLayers.Http != nil {
				t.Log("## http:", frameData.BaseLayers.Http)
				if frameData.BaseLayers.Http.ResponseLine != nil {
					for _, header := range *frameData.BaseLayers.Http.ResponseLine {
						t.Log("#### http.ResponseLine >>>", header)
					}
				}
			}

		}
	}()

	// set TLS config
	// macos test parse tls1.2
	// curl --tlsv1.2 --tls-max 1.2 --ciphers 'AES128-GCM-SHA256' -k 'https://192.168.xxx.xxx/?id=123'
	tls := TlsConf{
		DesegmentSslRecords:         true,
		DesegmentSslApplicationData: true,
		KeysList: []Key{
			{
				Ip:       "",
				Port:     443,
				Protocol: "",
				KeyFile:  "./pcaps/server.key", // mac test key
				Password: "",
			},
		},
	}

	t.Log(tls)

	// start c client, capture and dissect packet
	err := DissectPktLive(ifName, filter, pktNum, promisc, timeout, WithTls(tls))
	if err != nil {
		t.Fatal(err)
	}
}

func TestBPF(t *testing.T) {
	ifName := "en7"
	filter := "tcp" // tcp port 443
	pktNum := 300
	promisc := 1
	timeout := 5

	var wg sync.WaitGroup
	defer wg.Wait()

	DissectResChans[ifName] = make(chan FrameDissectRes, 100)
	defer close(DissectResChans[ifName])

	wg.Add(1)

	go func() {
		defer wg.Done()
		for frameData := range DissectResChans[ifName] {
			t.Log("# Frame index:", frameData.BaseLayers.Frame.Number, "===========================")
			t.Log("【layer _ws.col.protocol】:", frameData.BaseLayers.WsCol.Protocol)

			if frameData.BaseLayers.Ip != nil {
				t.Log("## ip.src:", frameData.BaseLayers.Ip.Src)
				t.Log("## ip.dst:", frameData.BaseLayers.Ip.Dst)
			}
			if frameData.BaseLayers.Udp != nil {
				t.Log("## udp.srcport:", frameData.BaseLayers.Udp.SrcPort)
			}
			if frameData.BaseLayers.Tcp != nil {
				t.Log("## tcp.dstport:", frameData.BaseLayers.Tcp.DstPort)
			}
			if frameData.BaseLayers.Http != nil {
				t.Log("## http:", frameData.BaseLayers.Http)
				if frameData.BaseLayers.Http.ResponseLine != nil {
					for _, header := range *frameData.BaseLayers.Http.ResponseLine {
						t.Log("#### http.ResponseLine >>>", header)
					}
				}
			}

		}
	}()

	// start c client, capture and dissect packet
	err := DissectPktLive(ifName, filter, pktNum, promisc, timeout)
	if err != nil {
		t.Fatal(err)
	}
}
