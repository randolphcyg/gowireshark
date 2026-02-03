package pkg

import (
	"testing"

	"github.com/bytedance/sonic"
	"github.com/pkg/errors"
)

/*
Parse Ethernet
*/
func TestParseEth(t *testing.T) {
	pcapPath := "../pcaps/https.pcapng"
	frame, err := GetFrameByIdx(pcapPath, 14, PrintCJson(true), WithDebug(true))
	if err != nil {
		t.Fatal(err)
	}

	t.Log("# Frame index:", frame.BaseLayers.Frame.Number, "===========================")
	t.Log("【layer _ws.col.protocol】:", frame.BaseLayers.WsCol.Protocol)

	if frame.BaseLayers.Eth != nil {
		t.Log("## eth.src:", frame.BaseLayers.Eth.Src)
		t.Log("## eth.dst:", frame.BaseLayers.Eth.Dst)
	} else {
		t.Error("fail to parse tls!")
	}
}

/*
DEMO: parse SSLv1.2
*/
func TestParseHttps(t *testing.T) {
	pcapPath := "../pcaps/https.pcapng"

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

	frame, err := GetFrameByIdx(pcapPath, 14,
		PrintCJson(true), WithTls(tls), WithDebug(true))
	if err != nil {
		t.Fatal(err)
	}

	t.Log("# Frame index:", frame.BaseLayers.Frame.Number, "===========================")
	t.Log("【layer _ws.col.protocol】:", frame.BaseLayers.WsCol.Protocol)

	if frame.BaseLayers.Ip != nil {
		t.Log("## ip.src:", frame.BaseLayers.Ip.Src)
		t.Log("## ip.dst:", frame.BaseLayers.Ip.Dst)
	}
	if frame.BaseLayers.Udp != nil {
		t.Log("## udp.srcport:", frame.BaseLayers.Udp.SrcPort)
	}
	if frame.BaseLayers.Tcp != nil {
		t.Log("## tcp.dstport:", frame.BaseLayers.Tcp.DstPort)
	}
	if frame.BaseLayers.Http != nil {
		t.Log("## http:", frame.BaseLayers.Http)
		if frame.BaseLayers.Http[0].ResponseLine != nil {
			for _, header := range *frame.BaseLayers.Http[0].ResponseLine {
				t.Log("#### http.ResponseLine >>>", header)
			}
		}
	} else {
		t.Error("fail to parse tls!")
	}
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

	jsonData, err := sonic.Marshal(src)
	if err != nil {
		return nil, err
	}
	err = sonic.Unmarshal(jsonData, &p)
	if err != nil {
		return nil, ErrParseFrame
	}

	return p, nil
}

func TestParseCustomProtocol(t *testing.T) {
	frame, err := GetFrameByIdx(inputFilepath, 65,
		PrintCJson(true), WithDebug(true))
	if err != nil {
		t.Fatal(err)
	}

	// init ParserRegistry
	registry := NewParserRegistry()
	// register MySQL protocol Parser
	registry.Register("mysql", &MySQLLayer{})

	parsedLayer, err := registry.ParseProtocol("mysql", frame.Layers)
	if err != nil {
		t.Error("Error parsing MySQL protocol:", err)
	}

	mysqlLayer, ok := parsedLayer.(*MySQLLayer)
	if !ok {
		t.Error("Error parsing MySQL protocol:", err)
	}

	t.Log("Parsed MySQL layer, mysql.passwd:", mysqlLayer.LoginRequest.Password)
}
