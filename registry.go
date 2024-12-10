package gowireshark

import (
	"github.com/pkg/errors"
)

// ProtocolParser defines the interface for parsing a custom protocol.
type ProtocolParser interface {
	Parse(layers Layers) (interface{}, error)
}

// ParserRegistry manages the registered protocol parsers.
type ParserRegistry struct {
	parsers map[string]ProtocolParser
}

// NewParserRegistry creates and returns a new instance of ParserRegistry.
func NewParserRegistry() *ParserRegistry {
	return &ParserRegistry{
		parsers: make(map[string]ProtocolParser),
	}
}

// Register registers a protocol parser for a given protocol name.
func (r *ParserRegistry) Register(protocol string, parser ProtocolParser) {
	r.parsers[protocol] = parser
}

// GetParser retrieves the parser for a given protocol name.
func (r *ParserRegistry) GetParser(protocol string) (ProtocolParser, error) {
	parser, ok := r.parsers[protocol]
	if !ok {
		return nil, errors.Errorf("no parser for protocol %s", protocol)
	}
	return parser, nil
}

// ParseProtocol parses the given protocol using the registered parser.
func (r *ParserRegistry) ParseProtocol(protocol string, layers Layers) (any, error) {
	parser, exists := r.parsers[protocol]
	if !exists {
		return nil, errors.Errorf("protocol not registered: %s", protocol)
	}
	return parser.Parse(layers)
}
