package gowireshark

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/pkg/errors"
)

// FollowPayload is STABLE.
// FollowPayload contains one directional payload segment from a followed stream.
type FollowPayload struct {
	Dir     string `json:"dir"`
	HexData string `json:"hexData"`
	Bytes   []byte `json:"-"`
}

// FollowResult is STABLE.
// FollowResult contains payloads and summary metadata for a followed stream.
type FollowResult struct {
	Payloads    []FollowPayload `json:"payloads"`
	ClientNode  string          `json:"clientNode"`
	ServerNode  string          `json:"serverNode"`
	ClientBytes int             `json:"clientBytes"`
	ServerBytes int             `json:"serverBytes"`
	PacketCount int             `json:"packetCount"`
}

func newFollowPayload(dir, hexData string) FollowPayload {
	bytes, err := hex.DecodeString(hexData)
	if err != nil {
		return FollowPayload{Dir: dir, HexData: hexData}
	}
	return FollowPayload{Dir: dir, HexData: hexData, Bytes: bytes}
}

// FollowStream extracts payloads for TCP or UDP packets selected by a display filter.
// The protocol selector is always applied in addition to displayFilter.
//
// This is a convenience wrapper that creates a temporary Session.
func FollowStream(path string, displayFilter string, proto string, opts ...Option) (*FollowResult, error) {
	return FollowStreamContext(context.Background(), path, displayFilter, proto, opts...)
}

// FollowStreamContext extracts payloads using the provided context for session
// acquisition.
func FollowStreamContext(ctx context.Context, path string, displayFilter string, proto string, opts ...Option) (*FollowResult, error) {
	s, err := OpenSessionContext(ctx, path, opts...)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return s.FollowStream(Query{Filter: displayFilter}, proto)
}

func followStreamFromConf(displayFilter string, proto string) (*FollowResult, error) {
	if proto != "tcp" && proto != "udp" {
		return nil, errors.Wrapf(ErrUnsupportedProtocol, "%q (must be \"tcp\" or \"udp\")", proto)
	}

	effectiveFilter := proto
	if displayFilter != "" {
		if err := ValidateFilter(displayFilter); err != nil {
			return nil, err
		}
		effectiveFilter = fmt.Sprintf("(%s) && (%s)", proto, displayFilter)
	}

	return getStreamPayloadsBatch(effectiveFilter, proto)
}
