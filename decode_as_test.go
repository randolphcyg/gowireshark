package gowireshark

import (
	"testing"

	"github.com/randolphcyg/gowireshark/internal/testfixture"
)

func TestWithDecodeAsIPProto_NowSupported(t *testing.T) {
	pcap := testfixture.Pcap(t)

	frames, err := Frames(pcap, WithDecodeAs([]DecodeAsRule{{
		Table:    "ip.proto",
		Selector: "6",
		Protocol: "tcp",
	}}))
	if err != nil {
		t.Fatalf("Frames with ip.proto decode-as: %v", err)
	}
	if len(frames) == 0 {
		t.Fatal("expected non-empty frames with ip.proto decode-as")
	}
}

func TestWithDecodeAsMediaType_NowSupported(t *testing.T) {
	pcap := testfixture.Pcap(t)

	frames, err := Frames(pcap, WithDecodeAs([]DecodeAsRule{{
		Table:    "media_type",
		Selector: "application/json",
		Protocol: "http",
	}}))
	if err != nil {
		t.Fatalf("Frames with media_type decode-as: %v", err)
	}
	if len(frames) == 0 {
		t.Fatal("expected non-empty frames with media_type decode-as")
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

func TestWithDecodeAsUnsupportedTable(t *testing.T) {
	pcap := testfixture.Pcap(t)

	_, err := Frames(pcap, WithDecodeAs([]DecodeAsRule{{
		Table:    "nonexistent.table",
		Selector: "80",
		Protocol: "http",
	}}))
	if err == nil {
		t.Fatal("expected error for nonexistent decode-as table")
	}
}
