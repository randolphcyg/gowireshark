package gowireshark

import "C"
import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
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
	Debug       bool // debug mode
	Descriptive bool // with descriptive info
	Tls         TlsConf
}

type Option func(*Conf)

func WithTls(tls TlsConf) Option {
	return func(c *Conf) {
		c.Tls = tls
	}
}

// WithDebug set Debug mode
func WithDebug(debug bool) Option {
	return func(c *Conf) {
		c.Debug = debug
	}
}

// WithDescriptive with descriptive info
func WithDescriptive(debug bool) Option {
	return func(c *Conf) {
		c.Descriptive = debug
	}
}

func getDefaultDebug() bool {
	return os.Getenv("DEBUG") == "true"
}

func NewConfig(opts ...Option) *Conf {
	conf := &Conf{
		Debug: getDefaultDebug(), // export DEBUG=true
	}
	for _, opt := range opts {
		opt(conf)
	}
	return conf
}

// HandleTlsConf marshal TLS config
func HandleTlsConf(conf *Conf) string {
	tlsConf := make(map[string]string)
	if !reflect.DeepEqual(conf.Tls, TlsConf{}) {
		if conf.Tls.DesegmentSslRecords {
			tlsConf["tls.desegment_ssl_records"] = "TRUE"
		}
		if conf.Tls.DesegmentSslApplicationData {
			tlsConf["tls.desegment_ssl_application_data"] = "TRUE"
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
			tlsConf["tls.keys_list"] = strings.Join(keyValues, ";")
		}
	}

	if len(tlsConf) == 0 {
		return ""
	}

	jsonTlsConf, _ := json.Marshal(tlsConf)
	return string(jsonTlsConf)
}
