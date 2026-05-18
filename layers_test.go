package gowireshark

import (
	"github.com/randolphcyg/gowireshark/internal/testfixture"
	"testing"

	"github.com/bytedance/sonic"
	"github.com/pkg/errors"
)

// TestParseETH parses Ethernet layer from the first available pcap.
func TestParseETH(t *testing.T) {
	pcapPath := testfixture.Pcap(t)

	frame, err := FrameByIndex(pcapPath, 1, withCJSONOutput(true), WithDebug(true))
	if err != nil {
		t.Fatal(err)
	}

	t.Log("# Frame index:", frame.BaseLayers.Frame.Number)
	t.Log("Protocol:", frame.BaseLayers.WSCol.Protocol)

	if frame.BaseLayers.ETH != nil {
		t.Log("eth.src:", frame.BaseLayers.ETH.Src)
		t.Log("eth.dst:", frame.BaseLayers.ETH.Dst)
	} else {
		t.Log("No Ethernet layer in this frame")
	}
}

// TestParseHTTPs demonstrates TLS decryption (requires .key file in pcaps/).
func TestParseHTTPs(t *testing.T) {
	pcapPath := testfixture.Pcap(t)
	keyFile := testfixture.KeyFile(t)

	tls := TLSConfig{
		DesegmentSSLRecords:         true,
		DesegmentSSLApplicationData: true,
		KeysList: []TLSKey{
			{
				Port:     443,
				Protocol: "tls",
				KeyFile:  keyFile,
			},
		},
	}

	frame, err := FrameByIndex(pcapPath, 1,
		withCJSONOutput(true), WithTLS(tls), WithDebug(true))
	if err != nil {
		t.Fatal(err)
	}

	t.Log("# Frame index:", frame.BaseLayers.Frame.Number)
	t.Log("Protocol:", frame.BaseLayers.WSCol.Protocol)

	if frame.BaseLayers.IP != nil {
		t.Log("ip.src:", frame.BaseLayers.IP.Src)
		t.Log("ip.dst:", frame.BaseLayers.IP.Dst)
	}
	if frame.BaseLayers.TCP != nil {
		t.Log("tcp.dstport:", frame.BaseLayers.TCP.DstPort)
	}
	if frame.BaseLayers.HTTP != nil {
		t.Log("http layers found:", len(frame.BaseLayers.HTTP))
	}
}

// --- Custom protocol parsing demo ---

type MySQLCapsTree struct {
	CD string `json:"mysql.caps.cd"`
	CP string `json:"mysql.caps.cp"`
	CU string `json:"mysql.caps.cu"`
	FR string `json:"mysql.caps.fr"`
	IA string `json:"mysql.caps.ia"`
	II string `json:"mysql.caps.ii"`
	IS string `json:"mysql.caps.is"`
	LF string `json:"mysql.caps.lf"`
	LI string `json:"mysql.caps.li"`
	LP string `json:"mysql.caps.lp"`
	NS string `json:"mysql.caps.ns"`
	OB string `json:"mysql.caps.ob"`
	RS string `json:"mysql.caps.rs"`
	SC string `json:"mysql.caps.sc"`
	SL string `json:"mysql.caps.sl"`
	TA string `json:"mysql.caps.ta"`
}

type MySQLExtCapsTree struct {
	CA               string `json:"mysql.caps.ca"`
	CapExt           string `json:"mysql.caps.cap_ext"`
	CD               string `json:"mysql.caps.cd"`
	CompressZSD      string `json:"mysql.caps.compress_zsd"`
	DeprecateEOF     string `json:"mysql.caps.deprecate_eof"`
	EP               string `json:"mysql.caps.ep"`
	MFAuth           string `json:"mysql.caps.mf_auth"`
	MR               string `json:"mysql.caps.mr"`
	MS               string `json:"mysql.caps.ms"`
	OptionalMetadata string `json:"mysql.caps.optional_metadata"`
	PA               string `json:"mysql.caps.pa"`
	PM               string `json:"mysql.caps.pm"`
	QueryAttrs       string `json:"mysql.caps.query_attrs"`
	SessionTrack     string `json:"mysql.caps.session_track"`
	Unused           string `json:"mysql.caps.unused"`
	VC               string `json:"mysql.caps.vc"`
}

type MySQLLoginRequest struct {
	CapsClient        string           `json:"mysql.caps.client"`
	CapsClientTree    MySQLCapsTree    `json:"mysql.caps.client_tree"`
	ExtCapsClient     string           `json:"mysql.extcaps.client"`
	ExtCapsClientTree MySQLExtCapsTree `json:"mysql.extcaps.client_tree"`
	MaxPacket         string           `json:"mysql.max_packet"`
	Collation         string           `json:"mysql.collation"`
	User              string           `json:"mysql.user"`
	Password          string           `json:"mysql.passwd"`
	Schema            string           `json:"mysql.schema"`
	Unused            string           `json:"mysql.unused"`
	ClientAuthPlugin  string           `json:"mysql.client_auth_plugin"`
}

type MySQLLayer struct {
	PacketLength string            `json:"mysql.packet_length"`
	PacketNumber string            `json:"mysql.packet_number"`
	LoginRequest MySQLLoginRequest `json:"mysql.login_request"`
}

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

// TestParseCustomProtocol demonstrates custom protocol parsing via the registry.
// Requires a pcap containing MySQL traffic.
func TestParseCustomProtocol(t *testing.T) {
	pcapPath := testfixture.Pcap(t)

	frame, err := FrameByIndex(pcapPath, 1, withCJSONOutput(true), WithDebug(true))
	if err != nil {
		t.Fatal(err)
	}

	registry := NewParserRegistry()
	if err := registry.Register("mysql", &MySQLLayer{}); err != nil {
		t.Fatal(err)
	}

	parsedLayer, err := registry.ParseProtocol("mysql", frame.Layers)
	if err != nil {
		t.Skipf("MySQL layer not found in test pcap (expected if not MySQL traffic): %v", err)
		return
	}

	mysqlLayer, ok := parsedLayer.(*MySQLLayer)
	if !ok {
		t.Fatal("Type assertion to *MySQLLayer failed")
	}

	t.Log("Parsed MySQL layer, mysql.user:", mysqlLayer.LoginRequest.User)
}

// TestRegistryIntegration demonstrates that a supplied registry is invoked during parsing.
func TestRegistryIntegration(t *testing.T) {
	pcapPath := testfixture.Pcap(t)

	registry := NewParserRegistry()
	if err := registry.Register("mysql", &MySQLLayer{}); err != nil {
		t.Fatal(err)
	}

	frame, err := FrameByIndex(pcapPath, 1, withCJSONOutput(true), WithRegistry(registry))
	if err != nil {
		t.Fatal(err)
	}

	// If the pcap contains MySQL traffic, CustomLayers should have the result
	if frame.CustomLayers != nil {
		if mysqlRaw, ok := frame.CustomLayers["mysql"]; ok {
			mysqlLayer, ok := mysqlRaw.(*MySQLLayer)
			if !ok {
				t.Fatal("Type assertion to *MySQLLayer failed")
			}
			t.Log("Auto-parsed MySQL layer via explicit registry, mysql.user:", mysqlLayer.LoginRequest.User)
		}
	} else {
		t.Log("No custom layers parsed (expected if pcap does not contain MySQL traffic)")
	}
}
