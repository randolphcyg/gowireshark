package gowireshark

import (
	"fmt"
	"os"
	"reflect"
	"strings"

	"github.com/bytedance/sonic"
)

// TLSKey is STABLE.
// TLSKey configures one legacy TLS key-list entry.
type TLSKey struct {
	IP       string
	Port     int
	Protocol string
	KeyFile  string
	Password string
}

// TLSConfig is STABLE.
// TLSConfig controls Wireshark TLS dissection preferences.
type TLSConfig struct {
	DesegmentSSLRecords         bool
	DesegmentSSLApplicationData bool
	KeysList                    []TLSKey
	KeylogFile                  string
}

// DecodeAsRule is STABLE.
// DecodeAsRule forces a dissector table selector to use a protocol dissector.
// Supports uint tables (tcp.port, udp.port, sctp.port, ssl.port, http2.tcp.port,
// ethertype, ip.proto) and string tables (media_type).
type DecodeAsRule struct {
	Table    string `json:"table"`
	Selector string `json:"selector"`
	Protocol string `json:"protocol"`
}

// NameResolutionConfig is STABLE.
// NameResolutionConfig controls Wireshark's address name resolution.
type NameResolutionConfig struct {
	MAC       bool `json:"mac"`
	Network   bool `json:"network"`
	Transport bool `json:"transport"`
	External  bool `json:"external"`
}

// Preference is STABLE.
// Preference sets one Wireshark preference (equivalent to -o flag).
type Preference struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// SessionCacheOptions is STABLE.
// SessionCacheOptions controls in-memory cache behavior for Session operations.
type SessionCacheOptions struct {
	MaxPages       int
	MaxFollowBytes int64
	MaxIndexCount  int // max number of FrameIndex entries to retain (0 = unlimited)
	Disable        bool
}

// ParseMode is STABLE.
type ParseMode int

const (
	ParseBaseLayers ParseMode = iota
	ParseRawLayers
	ParseSelectedLayers
)

type config struct {
	IgnoreErrors    bool
	Debug           bool
	PrintCJSON      bool
	DisplayFilter   string
	OutputFields    []string
	CompactJSON     bool
	RawJSON         bool
	TLS             TLSConfig
	DecodeAs        []DecodeAsRule
	EnableTCPFollow bool
	Registry        *ParserRegistry
	NameResolution  *NameResolutionConfig
	Preferences     []Preference
	Profile         string
	FieldOutput     FieldOutputOptions
	FieldOccurrence FieldOccurrence
	ParseMode       ParseMode
	SelectedLayers  []string
	SessionCache    SessionCacheOptions
}

// Option is STABLE.
// Option customizes one dissection operation.
type Option func(*config)

// WithIgnoreErrors controls whether malformed frames are skipped during bulk parsing.
func WithIgnoreErrors(ignore bool) Option {
	return func(c *config) { c.IgnoreErrors = ignore }
}

func withCJSONOutput(print bool) Option {
	return func(c *config) { c.PrintCJSON = print }
}

// WithOutputFields limits writer-style JSON output to the requested Wireshark
// field names. It is currently honored by WriteFrames and WriteFramesJSONL.
func WithOutputFields(fields []string) Option {
	return func(c *config) {
		c.OutputFields = append([]string(nil), fields...)
	}
}

// WithCompactJSON requests compact JSON output from writer-style APIs. NDJSON
// writer APIs are compact by default; this option is kept for CLI-facing
// configuration symmetry.
func WithCompactJSON(compact bool) Option {
	return func(c *config) { c.CompactJSON = compact }
}

// WithRawJSON asks libwireshark to include its raw C JSON representation when
// supported by the underlying dissection path.
func WithRawJSON(raw bool) Option {
	return func(c *config) {
		c.RawJSON = raw
		c.PrintCJSON = raw
	}
}

// WithTCPFollow enables tcp_follow tap collection during offline parsing.
func WithTCPFollow(enabled bool) Option {
	return func(c *config) { c.EnableTCPFollow = enabled }
}

// WithTLS applies TLS dissection preferences.
func WithTLS(tls TLSConfig) Option {
	return func(c *config) { c.TLS = tls }
}

// WithDecodeAs applies Wireshark Decode As rules for one operation/session.
func WithDecodeAs(rules []DecodeAsRule) Option {
	return func(c *config) {
		c.DecodeAs = append([]DecodeAsRule(nil), rules...)
	}
}

// WithDebug enables debug logging in the underlying C layer.
func WithDebug(debug bool) Option {
	return func(c *config) { c.Debug = debug }
}

// WithDisplayFilter applies the frame-selection filter used by bulk file operations.
func WithDisplayFilter(filter string) Option {
	return func(c *config) { c.DisplayFilter = filter }
}

// WithRegistry attaches an explicit custom-protocol registry to one operation.
func WithRegistry(registry *ParserRegistry) Option {
	return func(c *config) { c.Registry = registry }
}

// WithNameResolution controls libwireshark address name resolution flags.
func WithNameResolution(cfg NameResolutionConfig) Option {
	return func(c *config) { c.NameResolution = &cfg }
}

// WithPreferences sets arbitrary Wireshark preferences (equivalent to -o).
func WithPreferences(prefs []Preference) Option {
	return func(c *config) { c.Preferences = append([]Preference(nil), prefs...) }
}

// WithProfile selects a Wireshark configuration profile by name.
func WithProfile(profile string) Option {
	return func(c *config) { c.Profile = profile }
}

// WithFieldOccurrence selects which occurrence FieldsRows returns for
// multi-value fields. OccurrenceAll is intentionally rejected by FieldsRows;
// use FieldsRowsValues for structured multi-value output.
func WithFieldOccurrence(occurrence FieldOccurrence) Option {
	return func(c *config) { c.FieldOccurrence = occurrence }
}

func WithParseMode(mode ParseMode) Option {
	return func(c *config) { c.ParseMode = mode }
}

func WithSelectedLayers(layers []string) Option {
	return func(c *config) { c.SelectedLayers = append([]string(nil), layers...) }
}

// WithSessionCache controls Session-level caching behavior.
func WithSessionCache(opts SessionCacheOptions) Option {
	return func(c *config) { c.SessionCache = opts }
}

func defaultDebug() bool { return os.Getenv("DEBUG") == "true" }

func newConfig(opts ...Option) *config {
	conf := &config{
		IgnoreErrors: true,
		Debug:        defaultDebug(),
	}
	for _, opt := range opts {
		opt(conf)
	}
	return conf
}

func validateDecodeAsRules(rules []DecodeAsRule) error {
	for _, rule := range rules {
		if rule.Table == "" {
			return fmt.Errorf("%w: empty decode-as table", ErrUnsupportedProtocol)
		}
		if rule.Protocol == "" {
			return fmt.Errorf("%w: empty decode-as protocol", ErrUnsupportedProtocol)
		}
		if rule.Selector == "" {
			return fmt.Errorf("%w: empty decode-as selector", ErrUnsupportedProtocol)
		}
	}
	return nil
}

func marshalConfig(conf *config) string {
	cConf := make(map[string]any)
	if conf.EnableTCPFollow {
		cConf["printTcpStreams"] = true
	}
	if len(conf.DecodeAs) > 0 {
		cConf["decode_as"] = conf.DecodeAs
	}
	if !reflect.DeepEqual(conf.TLS, TLSConfig{}) {
		if conf.TLS.DesegmentSSLRecords {
			cConf["tls.desegment_ssl_records"] = true
		}
		if conf.TLS.DesegmentSSLApplicationData {
			cConf["tls.desegment_ssl_application_data"] = true
		}
		if conf.TLS.KeylogFile != "" {
			cConf["tls.keylog_file"] = conf.TLS.KeylogFile
		}
		if conf.TLS.KeysList != nil {
			keyValues := make([]string, 0, len(conf.TLS.KeysList))
			for _, key := range conf.TLS.KeysList {
				parts := []string{
					key.IP,
					fmt.Sprintf("%d", key.Port),
					key.Protocol,
					key.KeyFile,
					key.Password,
				}
				for i, part := range parts {
					if part == "" || part == "0" {
						parts[i] = ""
					}
				}
				keyValues = append(keyValues, strings.Join(parts, ","))
			}
			cConf["tls.keys_list"] = strings.Join(keyValues, ";")
		}
	}
	if conf.NameResolution != nil {
		cConf["name_resolution"] = conf.NameResolution
	}
	if len(conf.Preferences) > 0 {
		cConf["preferences"] = conf.Preferences
	}
	if conf.Profile != "" {
		cConf["profile"] = conf.Profile
	}
	if len(cConf) == 0 {
		return ""
	}
	jsonCConf, _ := sonic.Marshal(cConf)
	return string(jsonCConf)
}
