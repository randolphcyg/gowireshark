package gowireshark

import (
	stderrors "errors"
	"testing"

	"github.com/randolphcyg/gowireshark/internal/testfixture"
)

func TestWithDecodeAsValidation(t *testing.T) {
	pcap := testfixture.Pcap(t)

	if _, err := Frames(pcap, WithDecodeAs([]DecodeAsRule{{
		Table:    "ip.proto",
		Selector: "6",
		Protocol: "tcp",
	}})); !stderrors.Is(err, ErrUnsupportedProtocol) {
		t.Fatalf("unsupported decode-as table error=%v, want ErrUnsupportedProtocol", err)
	}

	if _, err := Frames(pcap, WithDecodeAs([]DecodeAsRule{{
		Table:    "tcp.port",
		Selector: "99999",
		Protocol: "http",
	}})); !stderrors.Is(err, ErrUnsupportedProtocol) {
		t.Fatalf("invalid decode-as selector error=%v, want ErrUnsupportedProtocol", err)
	}
}

func TestWithDecodeAsDoesNotPolluteNextCall(t *testing.T) {
	pcap := testfixture.Pcap(t)

	if _, err := Frames(pcap, WithDecodeAs([]DecodeAsRule{{
		Table:    "tcp.port",
		Selector: "8080",
		Protocol: "http",
	}})); err != nil {
		t.Fatalf("Frames with decode-as: %v", err)
	}
	if _, err := Frames(pcap); err != nil {
		t.Fatalf("Frames after decode-as: %v", err)
	}
}
