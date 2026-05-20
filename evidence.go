package gowireshark

import (
	"bufio"
	"io"
	"os"
	"slices"

	"github.com/google/gopacket"
	gplayers "github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/pkg/errors"
)

// FrameRange is an inclusive 1-based frame-number range.
type FrameRange struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

// FrameSelector selects frames for evidence operations. Indices and Range are
// 1-based frame numbers. When multiple selectors are provided, their results
// are unioned.
type FrameSelector struct {
	Filter  string     `json:"filter,omitempty"`
	Indices []int      `json:"indices,omitempty"`
	Range   FrameRange `json:"range,omitempty"`
}

// EvidenceBundle is a compact, reproducible evidence object for a selected set
// of frames and optional stream/file context.
type EvidenceBundle struct {
	Selector FrameSelector `json:"selector"`
	Frames   []*FrameData  `json:"frames,omitempty"`
	Hex      []*HexData    `json:"hex,omitempty"`
	Follow   *FollowResult `json:"follow,omitempty"`
	Files    []FileObject  `json:"files,omitempty"`
}

// SelectedFrameNumbers resolves a selector to sorted unique 1-based frame numbers.
func SelectedFrameNumbers(path string, selector FrameSelector, opts ...Option) ([]int, error) {
	set := map[int]bool{}
	for _, idx := range selector.Indices {
		if idx < 1 {
			return nil, errors.Wrapf(ErrInvalidFrameIndex, "%d", idx)
		}
		set[idx] = true
	}
	if selector.Range.Start != 0 || selector.Range.End != 0 {
		if selector.Range.Start < 1 || selector.Range.End < selector.Range.Start {
			return nil, errors.Wrapf(ErrInvalidFrameIndex, "range %d-%d", selector.Range.Start, selector.Range.End)
		}
		for i := selector.Range.Start; i <= selector.Range.End; i++ {
			set[i] = true
		}
	}
	if selector.Filter != "" {
		if err := ValidateFilter(selector.Filter); err != nil {
			return nil, err
		}
		err := WalkFrames(path, func(f *FrameData) error {
			if f != nil && f.BaseLayers.Frame != nil {
				set[f.BaseLayers.Frame.Number] = true
			}
			return nil
		}, append(opts, WithDisplayFilter(selector.Filter))...)
		if err != nil {
			return nil, err
		}
	}
	if len(set) == 0 {
		return nil, ErrEmptySelection
	}
	out := make([]int, 0, len(set))
	for idx := range set {
		out = append(out, idx)
	}
	slices.Sort(out)
	return out, nil
}

// WritePcapSlice writes selected packets to w in libpcap/pcapng format using
// best-effort pcapgo conversion (not native wiretap). Selection is by 1-based
// frame numbers and/or Wireshark display filter.
func WritePcapSlice(path string, w io.Writer, selector FrameSelector, opts ...Option) (int, error) {
	indices, err := SelectedFrameNumbers(path, selector, opts...)
	if err != nil {
		return 0, err
	}
	return writePcapSliceByIndices(path, w, indices)
}

// PcapSliceOptions controls output format and metadata preservation for
// best-effort pcap slicing via pcapgo (not native wiretap).
//
// PreserveComments and PreserveInterfaces are NOT supported by the current
// pcapgo implementation and will return ErrPreserveNotSupported if enabled.
// Future native wiretap integration may add full metadata preservation.
type PcapSliceOptions struct {
	PreserveComments   bool
	PreserveInterfaces bool
	OutputFormat       string
}

// WritePcapSliceWithOptions writes selected packets to w with format control.
// OutputFormat can be "pcap", "pcapng", or "same" (auto-detect from input).
// This is a best-effort pcapgo-based implementation; PreserveComments and
// PreserveInterfaces are not yet supported.
func WritePcapSliceWithOptions(path string, w io.Writer, selector FrameSelector,
	sliceOpts PcapSliceOptions, opts ...Option) (int, error) {
	indices, err := SelectedFrameNumbers(path, selector, opts...)
	if err != nil {
		return 0, err
	}
	return writePcapSliceByIndicesWithOptions(path, w, indices, sliceOpts)
}

func writePcapSliceByIndicesWithOptions(path string, w io.Writer, indices []int, sliceOpts PcapSliceOptions) (int, error) {
	if len(indices) == 0 {
		return 0, ErrEmptySelection
	}
	if sliceOpts.PreserveComments || sliceOpts.PreserveInterfaces {
		return 0, ErrPreserveNotSupported
	}
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	forcePcap := sliceOpts.OutputFormat == "pcap"
	forceNg := sliceOpts.OutputFormat == "pcapng"

	br := bufio.NewReader(f)
	reader, err := pcapgo.NewReader(br)
	if err == nil && !forceNg {
		writer := pcapgo.NewWriter(w)
		if err := writer.WriteFileHeader(reader.Snaplen(), reader.LinkType()); err != nil {
			return 0, err
		}
		return copySelectedPackets(reader, writer.WritePacket, indices)
	}

	if _, seekErr := f.Seek(0, io.SeekStart); seekErr != nil {
		return 0, err
	}
	ngReader, ngErr := pcapgo.NewNgReader(f, pcapgo.NgReaderOptions{
		WantMixedLinkType: false,
	})
	if ngErr != nil {
		if forceNg {
			return 0, errors.Wrap(ngErr, "failed to open as pcapng")
		}
		return 0, err
	}

	linkType := ngReader.LinkType()
	if linkType == gplayers.LinkTypeNull && ngReader.NInterfaces() > 0 {
		if intf, intfErr := ngReader.Interface(0); intfErr == nil {
			linkType = intf.LinkType
		}
	}

	if forcePcap {
		writer := pcapgo.NewWriter(w)
		if err := writer.WriteFileHeader(65535, linkType); err != nil {
			return 0, err
		}
		return copySelectedPackets(ngReader, writer.WritePacket, indices)
	}

	ngWriter, err := pcapgo.NewNgWriter(w, linkType)
	if err != nil {
		return 0, err
	}
	count, err := copySelectedPackets(ngReader, ngWriter.WritePacket, indices)
	flushErr := ngWriter.Flush()
	if err != nil {
		return count, err
	}
	return count, flushErr
}

// BuildEvidenceBundle gathers parsed frames, hex dumps, file metadata, and an
// optional followed stream into one evidence object.
func BuildEvidenceBundle(path string, selector FrameSelector, opts ...Option) (*EvidenceBundle, error) {
	indices, err := SelectedFrameNumbers(path, selector, opts...)
	if err != nil {
		return nil, err
	}
	frames, err := FramesByIndices(path, indices, opts...)
	if err != nil {
		return nil, err
	}
	bundle := &EvidenceBundle{Selector: selector, Frames: frames}
	for _, idx := range indices {
		h, err := HexDataByIndex(path, idx, opts...)
		if err == nil && h != nil {
			bundle.Hex = append(bundle.Hex, h)
		}
	}
	for _, f := range frames {
		bundle.Files = append(bundle.Files, filesFromFrame(f)...)
	}
	if selector.Filter != "" {
		if hasProtocol(frames, "tcp") {
			bundle.Follow, _ = FollowStream(path, selector.Filter, "tcp", opts...)
		} else if hasProtocol(frames, "udp") {
			bundle.Follow, _ = FollowStream(path, selector.Filter, "udp", opts...)
		}
	}
	return bundle, nil
}

func hasProtocol(frames []*FrameData, proto string) bool {
	for _, f := range frames {
		if f == nil {
			continue
		}
		if proto == "tcp" && f.BaseLayers.TCP != nil {
			return true
		}
		if proto == "udp" && f.BaseLayers.UDP != nil {
			return true
		}
	}
	return false
}

func writePcapSliceByIndices(path string, w io.Writer, indices []int) (int, error) {
	if len(indices) == 0 {
		return 0, ErrEmptySelection
	}
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	br := bufio.NewReader(f)
	reader, err := pcapgo.NewReader(br)
	if err == nil {
		writer := pcapgo.NewWriter(w)
		if err := writer.WriteFileHeader(reader.Snaplen(), reader.LinkType()); err != nil {
			return 0, err
		}
		return copySelectedPackets(reader, writer.WritePacket, indices)
	}

	if _, seekErr := f.Seek(0, io.SeekStart); seekErr != nil {
		return 0, err
	}
	ngReader, ngErr := pcapgo.NewNgReader(f, pcapgo.NgReaderOptions{WantMixedLinkType: false})
	if ngErr != nil {
		return 0, err
	}
	linkType := ngReader.LinkType()
	if linkType == gplayers.LinkTypeNull && ngReader.NInterfaces() > 0 {
		if intf, intfErr := ngReader.Interface(0); intfErr == nil {
			linkType = intf.LinkType
		}
	}
	ngWriter, err := pcapgo.NewNgWriter(w, linkType)
	if err != nil {
		return 0, err
	}
	count, err := copySelectedPackets(ngReader, ngWriter.WritePacket, indices)
	flushErr := ngWriter.Flush()
	if err != nil {
		return count, err
	}
	return count, flushErr
}

type packetDataReader interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
}

type packetWriterFunc func(gopacket.CaptureInfo, []byte) error

func copySelectedPackets(r packetDataReader, write packetWriterFunc, indices []int) (int, error) {
	target := 0
	written := 0
	for frameNo := 1; target < len(indices); frameNo++ {
		data, ci, err := r.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			return written, err
		}
		if frameNo != indices[target] {
			continue
		}
		if err := write(ci, data); err != nil {
			return written, err
		}
		written++
		for target < len(indices) && indices[target] <= frameNo {
			target++
		}
	}
	if written == 0 {
		return 0, ErrEmptySelection
	}
	return written, nil
}
