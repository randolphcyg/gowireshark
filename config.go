package gowireshark

import "C"
import (
	"fmt"
	"os"
	"reflect"
	"strings"

	"github.com/bytedance/sonic"
)

// Key tls key
type Key struct {
	Ip       string
	Port     int
	Protocol string
	KeyFile  string
	Password string
}

type TlsConf struct {
	DesegmentSslRecords         bool
	DesegmentSslApplicationData bool
	KeysList                    []Key
}

type Conf struct {
	IgnoreError     bool    // Whether to ignore errors (default: true)
	Debug           bool    // Debug mode (default: from environment variable DEBUG)
	PrintCJson      bool    // Whether to print C JSON (default: false)
	Tls             TlsConf // TLS configuration
	PrintTcpStreams bool    // Whether to print TCP stream (default: false)
}

type Option func(*Conf)

// IgnoreError Whether to ignore the errors
func IgnoreError(ignore bool) Option {
	return func(c *Conf) {
		c.IgnoreError = ignore
	}
}

// PrintCJson controls whether to print the C JSON.
func PrintCJson(print bool) Option {
	return func(c *Conf) {
		c.PrintCJson = print
	}
}

// PrintTcpStreams controls Whether to print TCP stream.
func PrintTcpStreams(print bool) Option {
	return func(c *Conf) {
		c.PrintTcpStreams = print
	}
}

// WithTls sets the TLS configuration.
func WithTls(tls TlsConf) Option {
	return func(c *Conf) {
		c.Tls = tls
	}
}

// WithDebug sets the application to debug mode.
func WithDebug(debug bool) Option {
	return func(c *Conf) {
		c.Debug = debug
	}
}

// getDefaultDebug reads the DEBUG environment variable to determine whether debug mode should be enabled.
func getDefaultDebug() bool {
	return os.Getenv("DEBUG") == "true"
}

// NewConfig creates a new Conf instance with the given options, applying defaults where necessary.
func NewConfig(opts ...Option) *Conf {
	conf := &Conf{
		PrintCJson:      false,             // Default: Do not print C JSON
		PrintTcpStreams: false,             // Default: Do not print TCP stream
		IgnoreError:     true,              // Default: Ignore errors
		Debug:           getDefaultDebug(), // Default: Check DEBUG environment variable for debug mode
	}
	for _, opt := range opts {
		opt(conf)
	}
	return conf
}

// HandleConf marshal TLS config
func HandleConf(conf *Conf) string {
	cConf := make(map[string]any)

	if conf.PrintTcpStreams {
		cConf["printTcpStreams"] = true
	}

	// handle TLS config
	if !reflect.DeepEqual(conf.Tls, TlsConf{}) {
		if conf.Tls.DesegmentSslRecords {
			cConf["tls.desegment_ssl_records"] = true
		}
		if conf.Tls.DesegmentSslApplicationData {
			cConf["tls.desegment_ssl_application_data"] = true
		}
		if conf.Tls.KeysList != nil {
			var keyValues []string
			for _, key := range conf.Tls.KeysList {
				parts := []string{
					key.Ip,
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

				// [IP,port,protocol,KeyFile,pwd]
				keyValue := fmt.Sprintf("%s", strings.Join(parts, ","))
				keyValues = append(keyValues, keyValue)
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
