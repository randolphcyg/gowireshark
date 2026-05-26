package gowireshark

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"testing"

	"github.com/google/gopacket/pcapgo"
	"github.com/randolphcyg/gowireshark/internal/testfixture"
)

func TestSelectedFrameNumbersRangeValidation(t *testing.T) {
	_, err := SelectedFrameNumbers("unused.pcap", FrameSelector{Range: FrameRange{Start: 3, End: 2}})
	if !errors.Is(err, ErrInvalidFrameNumber) {
		t.Fatalf("expected ErrInvalidFrameNumber, got %v", err)
	}
}

func TestWritePcapSliceByRange(t *testing.T) {
	pcap := testfixture.Pcap(t)
	var buf bytes.Buffer
	count, err := WritePcapSlice(pcap, &buf, FrameSelector{Range: FrameRange{Start: 1, End: 1}})
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("count: want 1 got %d", count)
	}
	if buf.Len() == 0 {
		t.Fatal("expected pcap bytes")
	}
}

func TestWritePcapSliceNativePreserveInterfaces(t *testing.T) {
	pcap := testfixture.Pcap(t)
	var buf bytes.Buffer
	count, err := WritePcapSliceWithOptions(pcap, &buf,
		FrameSelector{Range: FrameRange{Start: 1, End: 1}},
		PcapSliceOptions{PreserveInterfaces: true})
	if err != nil {
		t.Fatalf("native PreserveInterfaces should work: %v", err)
	}
	if count != 1 {
		t.Fatalf("count: want 1 got %d", count)
	}
	if buf.Len() == 0 {
		t.Fatal("expected pcap bytes")
	}
}

func TestWritePcapSliceNativePreserveComments(t *testing.T) {
	pcap := testfixture.Pcap(t)
	var buf bytes.Buffer
	count, err := WritePcapSliceWithOptions(pcap, &buf,
		FrameSelector{Range: FrameRange{Start: 1, End: 1}},
		PcapSliceOptions{PreserveComments: true})
	if err != nil {
		t.Fatalf("native PreserveComments should work: %v", err)
	}
	if count != 1 {
		t.Fatalf("count: want 1 got %d", count)
	}
	if buf.Len() == 0 {
		t.Fatal("expected pcap bytes")
	}
}

func TestWritePcapSliceNativeExplicitFormat(t *testing.T) {
	pcap := testfixture.Pcap(t)
	var buf bytes.Buffer
	count, err := WritePcapSliceWithOptions(pcap, &buf,
		FrameSelector{Range: FrameRange{Start: 1, End: 1}},
		PcapSliceOptions{OutputFormat: PcapOutputPcapNG})
	if err != nil {
		t.Fatalf("native pcapng format should work: %v", err)
	}
	if count != 1 {
		t.Fatalf("count: want 1 got %d", count)
	}
	if buf.Len() == 0 {
		t.Fatal("expected pcap bytes")
	}
}

func TestWritePcapSliceNativeEmptyIndices(t *testing.T) {
	pcap := testfixture.Pcap(t)
	var buf bytes.Buffer
	_, err := WritePcapSliceWithOptions(pcap, &buf,
		FrameSelector{Range: FrameRange{Start: 99999, End: 99999}},
		PcapSliceOptions{PreserveInterfaces: true})
	if err == nil {
		t.Fatal("expected error for out-of-range indices")
	}
}

func TestWritePcapSliceNativeOutputReadable(t *testing.T) {
	pcap := testfixture.Pcap(t)
	var buf bytes.Buffer
	count, err := WritePcapSliceWithOptions(pcap, &buf,
		FrameSelector{Range: FrameRange{Start: 1, End: 2}},
		PcapSliceOptions{PreserveInterfaces: true})
	if err != nil {
		t.Fatalf("native write should succeed: %v", err)
	}
	if count != 2 {
		t.Fatalf("count: want 2 got %d", count)
	}

	tmpPath := writeTempPcap(t, buf.Bytes())
	defer cleanupTempPcap(t, tmpPath)

	frameCount, err := FrameCount(tmpPath)
	if err != nil {
		t.Fatalf("should be able to read back native output: %v", err)
	}
	if frameCount != 2 {
		t.Fatalf("frame count in output: want 2 got %d", frameCount)
	}
}

func TestWritePcapSliceNativeRejectsInvalidFormat(t *testing.T) {
	pcap := testfixture.Pcap(t)
	var buf bytes.Buffer
	_, err := WritePcapSliceWithOptions(pcap, &buf,
		FrameSelector{Range: FrameRange{Start: 1, End: 1}},
		PcapSliceOptions{OutputFormat: PcapOutputFormat("invalid")})
	if !errors.Is(err, ErrUnsupportedOutputFormat) {
		t.Fatalf("error=%v, want ErrUnsupportedOutputFormat", err)
	}
}

func TestSelectedFrameNumbersWithFilter(t *testing.T) {
	pcap := testfixture.Pcap(t)

	got, err := SelectedFrameNumbers(pcap, FrameSelector{Filter: "frame.number <= 3"})
	if err != nil {
		t.Fatalf("SelectedFrameNumbers filter: %v", err)
	}
	want := []int{1, 2, 3}
	if len(got) != len(want) {
		t.Fatalf("numbers length: want %d got %d (%v)", len(want), len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("numbers[%d]: want %d got %d", i, want[i], got[i])
		}
	}
}

func TestWritePcapSliceNativePreservesPcapNGMetadata(t *testing.T) {
	input := writeTempPcap(t, commentedPcapNG())
	var buf bytes.Buffer

	count, err := WritePcapSliceWithOptions(input, &buf,
		FrameSelector{Range: FrameRange{Start: 1, End: 1}},
		PcapSliceOptions{PreserveComments: true, PreserveInterfaces: true, OutputFormat: PcapOutputPcapNG})
	if err != nil {
		t.Fatalf("native metadata-preserving slice: %v", err)
	}
	if count != 1 {
		t.Fatalf("count: want 1 got %d", count)
	}

	out := buf.Bytes()
	for _, want := range [][]byte{
		[]byte("gowireshark-interface-name"),
		[]byte("gowireshark-interface-comment"),
		[]byte("gowireshark-packet-comment"),
	} {
		if !bytes.Contains(out, want) {
			t.Fatalf("output did not preserve metadata %q", want)
		}
	}

	r, err := pcapgo.NewNgReader(bytes.NewReader(out), pcapgo.DefaultNgReaderOptions)
	if err != nil {
		t.Fatalf("read native pcapng output: %v", err)
	}
	if r.NInterfaces() == 0 {
		t.Fatal("expected at least one interface")
	}
	intf, err := r.Interface(0)
	if err != nil {
		t.Fatalf("read interface metadata: %v", err)
	}
	if intf.Name != "gowireshark-interface-name" {
		t.Fatalf("interface name: want %q got %q", "gowireshark-interface-name", intf.Name)
	}
	if intf.Comment != "gowireshark-interface-comment" {
		t.Fatalf("interface comment: want %q got %q", "gowireshark-interface-comment", intf.Comment)
	}
}

func commentedPcapNG() []byte {
	var out bytes.Buffer

	section := bytes.NewBuffer(nil)
	binary.Write(section, binary.LittleEndian, uint32(0x1A2B3C4D))
	binary.Write(section, binary.LittleEndian, uint16(1))
	binary.Write(section, binary.LittleEndian, uint16(0))
	binary.Write(section, binary.LittleEndian, uint64(0xffffffffffffffff))
	writePcapNGBlock(&out, 0x0A0D0D0A, section.Bytes())

	idb := bytes.NewBuffer(nil)
	binary.Write(idb, binary.LittleEndian, uint16(1))
	binary.Write(idb, binary.LittleEndian, uint16(0))
	binary.Write(idb, binary.LittleEndian, uint32(65535))
	writePcapNGOption(idb, 2, []byte("gowireshark-interface-name"))
	writePcapNGOption(idb, 1, []byte("gowireshark-interface-comment"))
	writePcapNGOption(idb, 0, nil)
	writePcapNGBlock(&out, 1, idb.Bytes())

	packet := make([]byte, 60)
	copy(packet[0:6], []byte{0, 1, 2, 3, 4, 5})
	copy(packet[6:12], []byte{6, 7, 8, 9, 10, 11})
	packet[12] = 0x08
	packet[13] = 0x00

	epb := bytes.NewBuffer(nil)
	binary.Write(epb, binary.LittleEndian, uint32(0))
	binary.Write(epb, binary.LittleEndian, uint32(0))
	binary.Write(epb, binary.LittleEndian, uint32(1))
	binary.Write(epb, binary.LittleEndian, uint32(len(packet)))
	binary.Write(epb, binary.LittleEndian, uint32(len(packet)))
	epb.Write(packet)
	writePcapNGPadding(epb, len(packet))
	writePcapNGOption(epb, 1, []byte("gowireshark-packet-comment"))
	writePcapNGOption(epb, 0, nil)
	writePcapNGBlock(&out, 6, epb.Bytes())

	return out.Bytes()
}

func writePcapNGBlock(w *bytes.Buffer, blockType uint32, body []byte) {
	totalLen := uint32(12 + len(body))
	binary.Write(w, binary.LittleEndian, blockType)
	binary.Write(w, binary.LittleEndian, totalLen)
	w.Write(body)
	binary.Write(w, binary.LittleEndian, totalLen)
}

func writePcapNGOption(w *bytes.Buffer, code uint16, value []byte) {
	binary.Write(w, binary.LittleEndian, code)
	binary.Write(w, binary.LittleEndian, uint16(len(value)))
	w.Write(value)
	writePcapNGPadding(w, len(value))
}

func writePcapNGPadding(w *bytes.Buffer, n int) {
	if padding := (4 - n%4) % 4; padding > 0 {
		w.Write(make([]byte, padding))
	}
}

func writeTempPcap(t testing.TB, data []byte) string {
	t.Helper()
	tmp, err := os.CreateTemp("", "gowireshark-test-*.pcap")
	if err != nil {
		t.Fatal(err)
	}
	path := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(path)
		t.Fatal(err)
	}
	tmp.Close()
	t.Cleanup(func() { os.Remove(path) })
	return path
}

func cleanupTempPcap(t testing.TB, path string) {
	t.Helper()
	os.Remove(path)
}
