package gowireshark

import (
	"fmt"
	"os"
	"reflect"
	"strings"

	"github.com/bytedance/sonic"
)

// TLSKey configures one legacy TLS key-list entry.
type TLSKey struct {
	IP       string
	Port     int
	Protocol string
	KeyFile  string
	Password string
}

// TLSConfig controls Wireshark TLS dissection preferences.
type TLSConfig struct {
	DesegmentSSLRecords         bool
	DesegmentSSLApplicationData bool
	KeysList                    []TLSKey
	KeylogFile                  string
}

type config struct {
	IgnoreErrors    bool
	Debug           bool
	PrintCJSON      bool
	DisplayFilter   string
	TLS             TLSConfig
	EnableTCPFollow bool
	Registry        *ParserRegistry
}

// Option customizes one dissection operation.
type Option func(*config)

// WithIgnoreErrors controls whether malformed frames are skipped during bulk parsing.
func WithIgnoreErrors(ignore bool) Option {
	return func(c *config) { c.IgnoreErrors = ignore }
}

func withCJSONOutput(print bool) Option {
	return func(c *config) { c.PrintCJSON = print }
}

// WithTCPFollow enables tcp_follow tap collection during offline parsing.
func WithTCPFollow(enabled bool) Option {
	return func(c *config) { c.EnableTCPFollow = enabled }
}

// WithTLS applies TLS dissection preferences.
func WithTLS(tls TLSConfig) Option {
	return func(c *config) { c.TLS = tls }
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

func marshalConfig(conf *config) string {
	cConf := make(map[string]any)
	if conf.EnableTCPFollow {
		cConf["printTcpStreams"] = true
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
	if len(cConf) == 0 {
		return ""
	}
	jsonCConf, _ := sonic.Marshal(cConf)
	return string(jsonCConf)
}
