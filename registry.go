package gowireshark

import (
	"log/slog"
	"slices"
	"sync"

	"github.com/pkg/errors"
)

var (
	// ErrProtocolEmpty reports an empty custom-protocol name.
	ErrProtocolEmpty = errors.New("protocol name cannot be empty")
	// ErrParserNil reports a nil custom-protocol parser.
	ErrParserNil = errors.New("parser cannot be nil")
	// ErrProtocolNotFound reports a lookup for an unregistered custom protocol.
	ErrProtocolNotFound = errors.New("protocol not registered")
)

// ProtocolParser defines the interface for parsing a custom protocol layer.
// Implementations should extract protocol-specific fields from the raw Layers map.
type ProtocolParser interface {
	// Parse extracts and returns the typed protocol data from the raw layers.
	Parse(layers Layers) (any, error)
}

// ParserRegistry manages registered protocol parsers.
// It is safe for concurrent use.
type ParserRegistry struct {
	mu      sync.RWMutex
	parsers map[string]ProtocolParser
}

// NewParserRegistry creates and returns a new instance of ParserRegistry.
func NewParserRegistry() *ParserRegistry {
	return &ParserRegistry{
		parsers: make(map[string]ProtocolParser),
	}
}

// Register registers a protocol parser for a given protocol name.
// It is safe for concurrent use.
func (r *ParserRegistry) Register(protocol string, parser ProtocolParser) error {
	if protocol == "" {
		return ErrProtocolEmpty
	}
	if parser == nil {
		return ErrParserNil
	}

	r.mu.Lock()
	r.parsers[protocol] = parser
	r.mu.Unlock()

	slog.Debug("Protocol parser registered", "protocol", protocol)
	return nil
}

// Unregister removes a protocol parser by name.
func (r *ParserRegistry) Unregister(protocol string) {
	r.mu.Lock()
	delete(r.parsers, protocol)
	r.mu.Unlock()
}

// Parser retrieves the parser for a given protocol name.
func (r *ParserRegistry) Parser(protocol string) (ProtocolParser, error) {
	r.mu.RLock()
	parser, ok := r.parsers[protocol]
	r.mu.RUnlock()

	if !ok {
		return nil, errors.Wrapf(ErrProtocolNotFound, "%s", protocol)
	}
	return parser, nil
}

// ParseProtocol parses the given protocol using the registered parser.
func (r *ParserRegistry) ParseProtocol(protocol string, layers Layers) (any, error) {
	parser, err := r.Parser(protocol)
	if err != nil {
		return nil, err
	}
	return parser.Parse(layers)
}

// ParseAll attempts to parse all registered protocols against the given layers.
// Returns a map of protocol name → parsed result for protocols that were found.
// Protocols not present in the frame are silently skipped.
func (r *ParserRegistry) ParseAll(layers Layers) map[string]any {
	r.mu.RLock()
	// Snapshot parser names under read lock to minimize lock hold time
	protocols := make([]string, 0, len(r.parsers))
	parsers := make([]ProtocolParser, 0, len(r.parsers))
	for name, p := range r.parsers {
		protocols = append(protocols, name)
		parsers = append(parsers, p)
	}
	r.mu.RUnlock()

	if len(protocols) == 0 {
		return nil
	}

	results := make(map[string]any)
	for i, parser := range parsers {
		result, err := parser.Parse(layers)
		if err != nil {
			// Skip protocols not present in this frame (ErrLayerNotFound is expected)
			if errors.Is(err, ErrLayerNotFound) {
				continue
			}
			slog.Debug("Custom protocol parse failed", "protocol", protocols[i], "err", err)
			continue
		}
		results[protocols[i]] = result
	}

	return results
}

// Protocols returns the list of registered protocol names.
func (r *ParserRegistry) Protocols() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.parsers))
	for name := range r.parsers {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// Len returns the number of registered parsers.
func (r *ParserRegistry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.parsers)
}
