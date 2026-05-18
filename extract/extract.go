package extract

import (
	"bufio"
	"embed"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/pkg/errors"

	"github.com/randolphcyg/gowireshark"
)

var (
	//go:embed mime_types.txt
	mimeTypesFile embed.FS

	validExtensions = make(map[string]bool)
	extMu           sync.RWMutex
)

// Pre-compiled regexps for Content-Disposition parsing (avoid recompilation per call).
var (
	reFilename     = regexp.MustCompile(`(?i)filename="?([^";\r\n]+)"?`)
	reFilenameUTF8 = regexp.MustCompile(`(?i)filename\*=utf-8''([^;,\r\n]+)`)
)

func init() {
	data, err := mimeTypesFile.ReadFile("mime_types.txt")
	if err != nil {
		slog.Warn("extract: failed to read embedded mime_types.txt", "err", err)
		return
	}

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) == 2 {
			ext, typ := parts[0], parts[1]
			if err := mime.AddExtensionType(ext, typ); err != nil {
				slog.Debug("extract: failed to add extension type", "ext", ext, "err", err)
			}
			extMu.Lock()
			validExtensions[ext] = true
			extMu.Unlock()
		}
	}
}

// --- Public API ---

// isValidFileExtension checks if a filename has a recognized file extension.
func isValidFileExtension(filename string) bool {
	ext := strings.ToLower(strings.TrimSpace(filepath.Ext(filename)))
	if ext == "" {
		return false
	}
	extMu.RLock()
	defer extMu.RUnlock()
	return validExtensions[ext]
}

// Extractor writes extracted files under one explicit output directory.
type Extractor struct {
	dir string
	mu  sync.Mutex
}

// New creates an Extractor rooted at dir.
func New(dir string) (*Extractor, error) {
	if dir == "" {
		return nil, errors.New("extract directory is required")
	}
	return &Extractor{dir: dir}, nil
}

// Dir returns the extractor output directory.
func (e *Extractor) Dir() string { return e.dir }

// ExtractedFile describes one object written to disk.
type ExtractedFile struct {
	Path     string `json:"path"`     // output file path
	Filename string `json:"filename"` // original filename
	Protocol string `json:"protocol"` // source protocol (http, ftp-data, tftp, smb, imf)
	Size     int64  `json:"size"`     // file size in bytes
	SrcAddr  string `json:"srcAddr"`  // source address (if available)
	DstAddr  string `json:"dstAddr"`  // destination address (if available)
}

// ExtractFiles extracts all file objects from parsed frames.
// Supports: HTTP, FTP-DATA, TFTP, SMB/SMB2, IMF (email attachments).
func (e *Extractor) Files(frames []*gowireshark.FrameData) ([]ExtractedFile, error) {
	if e.dir == "" {
		return nil, errors.New("e.dir not set")
	}
	if err := os.MkdirAll(e.dir, 0o755); err != nil {
		return nil, fmt.Errorf("create extract dir: %w", err)
	}

	var results []ExtractedFile

	for _, frame := range frames {
		if frame == nil {
			continue
		}

		// HTTP file extraction
		if frame.BaseLayers.HTTP != nil {
			for _, h := range frame.BaseLayers.HTTP {
				if h == nil || h.FileData == "" {
					continue
				}
				ef, err := e.extractHTTPObject(h, frame)
				if err != nil {
					continue
				}
				results = append(results, ef)
			}
		}

		// Protocol-agnostic extraction via raw layers
		// FTP-DATA, TFTP, SMB, IMF carry file data in specific dissector fields
		extracted := e.extractFromRawLayers(frame)
		results = append(results, extracted...)
	}

	return results, nil
}

// ExtractHTTPFile extracts file data from HTTP response layers and writes them to disk.
// Returns the list of file paths that were successfully written.
// This is the legacy API — prefer ExtractFiles for multi-protocol support.
func (e *Extractor) HTTPFiles(httpList []*gowireshark.HTTP) ([]string, error) {
	if e.dir == "" {
		return nil, errors.New("e.dir not set")
	}
	if err := os.MkdirAll(e.dir, 0o755); err != nil {
		return nil, fmt.Errorf("create extract dir: %w", err)
	}

	var paths []string
	var extractErrors []error

	for _, h := range httpList {
		if h == nil || h.FileData == "" {
			continue
		}

		path, err := e.httpFilename(h)
		if err != nil {
			continue
		}

		if err := writeHexDataToFile(path, h.FileData); err != nil {
			extractErrors = append(extractErrors, fmt.Errorf("%s: %w", filepath.Base(path), err))
			continue
		}

		paths = append(paths, path)
	}

	if len(extractErrors) > 0 && len(paths) == 0 {
		return nil, fmt.Errorf("all extractions failed: %v", extractErrors[0])
	}

	return paths, nil
}

// --- HTTP Extraction ---

func (e *Extractor) extractHTTPObject(h *gowireshark.HTTP, frame *gowireshark.FrameData) (ExtractedFile, error) {
	path, err := e.httpFilename(h)
	if err != nil {
		return ExtractedFile{}, err
	}

	if err := writeHexDataToFile(path, h.FileData); err != nil {
		return ExtractedFile{}, err
	}

	info, _ := os.Stat(path)
	var size int64
	if info != nil {
		size = info.Size()
	}

	ef := ExtractedFile{
		Path:     path,
		Filename: filepath.Base(path),
		Protocol: "http",
		Size:     size,
	}

	if frame.BaseLayers.IP != nil {
		ef.SrcAddr = frame.BaseLayers.IP.Src
		ef.DstAddr = frame.BaseLayers.IP.Dst
	}

	return ef, nil
}

// --- Raw Layer Extraction (FTP-DATA, TFTP, SMB, IMF) ---

// extractFromRawLayers checks for file data in protocol-specific dissector fields.
func (e *Extractor) extractFromRawLayers(frame *gowireshark.FrameData) []ExtractedFile {
	if frame.Layers == nil {
		return nil
	}

	var results []ExtractedFile

	// FTP-DATA: carries raw file content in "ftp-data" layer
	if ef, ok := e.extractFTPData(frame); ok {
		results = append(results, ef)
	}

	// TFTP: carries file data in "tftp" layer with "tftp.data" field
	if ef, ok := e.extractTFTPData(frame); ok {
		results = append(results, ef)
	}

	// IMF (Internet Message Format): email with attachments
	if ef, ok := e.extractIMFData(frame); ok {
		results = append(results, ef...)
	}

	// SMB/SMB2: file transfer via "smb2.write_data" or "smb.file_data"
	if ef, ok := e.extractSMBData(frame); ok {
		results = append(results, ef)
	}

	return results
}

func (e *Extractor) extractFTPData(frame *gowireshark.FrameData) (ExtractedFile, bool) {
	ftpDataRaw, ok := frame.Layers["ftp-data"]
	if !ok {
		return ExtractedFile{}, false
	}

	m, ok := ftpDataRaw.(map[string]any)
	if !ok {
		return ExtractedFile{}, false
	}

	// ftp-data.command contains the filename from the RETR/STOR command
	filename := layerString(m, "ftp-data.command")
	if filename == "" {
		filename = layerString(m, "ftp-data.current-working-directory")
	}
	if filename != "" {
		filename = filepath.Base(filename)
	}
	if filename == "" || filename == "." || filename == "/" {
		filename = "ftp_transfer"
	}

	// ftp-data.data contains the hex payload
	hexData := layerString(m, "ftp-data.data")
	if hexData == "" {
		return ExtractedFile{}, false
	}

	path := e.uniquePath(filename)
	if err := writeHexDataToFile(path, hexData); err != nil {
		slog.Debug("extract: ftp-data write failed", "err", err)
		return ExtractedFile{}, false
	}

	info, _ := os.Stat(path)
	var size int64
	if info != nil {
		size = info.Size()
	}

	ef := ExtractedFile{
		Path:     path,
		Filename: filepath.Base(path),
		Protocol: "ftp-data",
		Size:     size,
	}
	if frame.BaseLayers.IP != nil {
		ef.SrcAddr = frame.BaseLayers.IP.Src
		ef.DstAddr = frame.BaseLayers.IP.Dst
	}

	return ef, true
}

func (e *Extractor) extractTFTPData(frame *gowireshark.FrameData) (ExtractedFile, bool) {
	tftpRaw, ok := frame.Layers["tftp"]
	if !ok {
		return ExtractedFile{}, false
	}

	m, ok := tftpRaw.(map[string]any)
	if !ok {
		return ExtractedFile{}, false
	}

	// Only extract DATA packets (opcode 3)
	opcode := layerString(m, "tftp.opcode")
	if opcode != "3" {
		return ExtractedFile{}, false
	}

	hexData := layerString(m, "tftp.data")
	if hexData == "" {
		return ExtractedFile{}, false
	}

	filename := layerString(m, "tftp.source_file")
	if filename == "" {
		filename = layerString(m, "tftp.destination_file")
	}
	if filename == "" {
		filename = "tftp_transfer"
	}
	filename = filepath.Base(filename)

	path := e.uniquePath(filename)
	if err := writeHexDataToFile(path, hexData); err != nil {
		slog.Debug("extract: tftp write failed", "err", err)
		return ExtractedFile{}, false
	}

	info, _ := os.Stat(path)
	var size int64
	if info != nil {
		size = info.Size()
	}

	ef := ExtractedFile{
		Path:     path,
		Filename: filepath.Base(path),
		Protocol: "tftp",
		Size:     size,
	}
	if frame.BaseLayers.IP != nil {
		ef.SrcAddr = frame.BaseLayers.IP.Src
		ef.DstAddr = frame.BaseLayers.IP.Dst
	}

	return ef, true
}

func (e *Extractor) extractIMFData(frame *gowireshark.FrameData) ([]ExtractedFile, bool) {
	imfRaw, ok := frame.Layers["imf"]
	if !ok {
		return nil, false
	}

	m, ok := imfRaw.(map[string]any)
	if !ok {
		return nil, false
	}

	// IMF attachments are in "imf.attachment" or nested MIME parts
	// The actual file data is in the MIME entity body
	_ = m // IMF extraction requires MIME parsing which is complex
	// For now, check if there's a direct file_data field
	fileData := layerString(m, "imf.file_data")
	if fileData == "" {
		return nil, false
	}

	filename := layerString(m, "imf.content_disposition.filename")
	if filename == "" {
		filename = "email_attachment"
	}

	path := e.uniquePath(filename)
	if err := writeHexDataToFile(path, fileData); err != nil {
		return nil, false
	}

	info, _ := os.Stat(path)
	var size int64
	if info != nil {
		size = info.Size()
	}

	ef := ExtractedFile{
		Path:     path,
		Filename: filepath.Base(path),
		Protocol: "imf",
		Size:     size,
	}
	if frame.BaseLayers.IP != nil {
		ef.SrcAddr = frame.BaseLayers.IP.Src
		ef.DstAddr = frame.BaseLayers.IP.Dst
	}

	return []ExtractedFile{ef}, true
}

func (e *Extractor) extractSMBData(frame *gowireshark.FrameData) (ExtractedFile, bool) {
	// Try SMB2 first (more common in modern networks)
	for _, layerKey := range []string{"smb2", "smb"} {
		smbRaw, ok := frame.Layers[layerKey]
		if !ok {
			continue
		}

		m, ok := smbRaw.(map[string]any)
		if !ok {
			continue
		}

		// SMB2 write data
		hexData := layerString(m, layerKey+".write_data")
		if hexData == "" {
			hexData = layerString(m, layerKey+".file_data")
		}
		if hexData == "" {
			continue
		}

		filename := layerString(m, layerKey+".filename")
		if filename == "" {
			filename = "smb_transfer"
		}
		filename = filepath.Base(filename)

		path := e.uniquePath(filename)
		if err := writeHexDataToFile(path, hexData); err != nil {
			continue
		}

		info, _ := os.Stat(path)
		var size int64
		if info != nil {
			size = info.Size()
		}

		ef := ExtractedFile{
			Path:     path,
			Filename: filepath.Base(path),
			Protocol: layerKey,
			Size:     size,
		}
		if frame.BaseLayers.IP != nil {
			ef.SrcAddr = frame.BaseLayers.IP.Src
			ef.DstAddr = frame.BaseLayers.IP.Dst
		}

		return ef, true
	}

	return ExtractedFile{}, false
}

// --- Filename Utilities ---

func (e *Extractor) httpFilename(http *gowireshark.HTTP) (string, error) {
	if http == nil {
		return "", errors.New("nil http object")
	}
	if http.FileData == "" {
		return "", errors.New("no file data")
	}
	if http.ResponseCode == "404" || http.ResponseCode == "301" {
		return "", errors.New("ignore 404 or 301")
	}

	filename := ""

	// 1. Try Content-Disposition header
	if http.ResponseLine != nil {
		filename = extractFilenameFromHeaders(*http.ResponseLine)
	}

	// 2. Fall back to URL path
	if filename == "" {
		p := http.ResponseUrl
		if p == "" {
			p = http.RequestUri
		}
		if p != "" {
			filename = filepath.Base(p)
			filename, _ = url.QueryUnescape(strings.Split(filename, "?")[0])
		}
	}

	// 3. Validate filename
	if filename == "" || filename == "/" || filename == "." {
		filename = "tmp"
	}

	// 4. If no extension, try to infer from Content-Type
	if filepath.Ext(filename) == "" && http.ContentType != "" {
		extensions, _ := mime.ExtensionsByType(http.ContentType)
		if len(extensions) > 0 {
			filename += extensions[0]
		}
	}

	// 5. If extension is not recognized, use "tmp" as base
	if !isValidFileExtension(filename) && filepath.Ext(filename) == "" {
		filename = "tmp"
	}

	return e.uniquePath(filename), nil
}

// extractFilenameFromHeaders parses Content-Disposition headers to find a filename.
func extractFilenameFromHeaders(headers []string) string {
	for _, line := range headers {
		lower := strings.ToLower(line)

		// RFC 5987: filename*=UTF-8''encoded%20name.pdf (higher priority)
		if strings.Contains(lower, "filename*=") {
			if match := reFilenameUTF8.FindStringSubmatch(line); len(match) > 1 {
				if decoded, err := urlStringDecode(match[1]); err == nil {
					return sanitizeFilename(decoded)
				}
			}
		}

		// Standard: filename="example.pdf"
		if strings.Contains(lower, "filename=") {
			if match := reFilename.FindStringSubmatch(line); len(match) > 1 {
				return sanitizeFilename(match[1])
			}
		}
	}
	return ""
}

// sanitizeFilename removes path separators and dangerous characters from a filename.
func sanitizeFilename(name string) string {
	name = strings.TrimSpace(name)
	// Remove path components
	name = filepath.Base(name)
	// Remove null bytes and control characters
	name = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, name)
	// Replace path separators
	name = strings.ReplaceAll(name, "/", "_")
	name = strings.ReplaceAll(name, "\\", "_")
	return name
}

// generateUniquePath creates a unique file path in e.dir.
func (e *Extractor) uniquePath(filename string) string {
	path := filepath.Join(e.dir, filename)
	if !fileExists(path) {
		return path
	}
	return e.uniqueFilename(filename)
}

// uniqueFilename generates a unique file path by appending an incrementing number.
func (e *Extractor) uniqueFilename(filename string) string {
	e.mu.Lock()
	defer e.mu.Unlock()

	ext := filepath.Ext(filename)
	base := strings.TrimSuffix(filename, ext)
	counter := 1

	for {
		path := filepath.Join(e.dir, filename)
		if !fileExists(path) {
			return path
		}
		filename = fmt.Sprintf("%s(%d)%s", base, counter, ext)
		counter++
	}
}

// urlStringDecode decodes a URL-encoded string.
func urlStringDecode(encoded string) (string, error) {
	return url.QueryUnescape(encoded)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func layerString(m map[string]any, key string) string {
	value, ok := m[key]
	if !ok {
		return ""
	}
	s, _ := value.(string)
	return s
}

// --- I/O ---

// writeHexDataToFile decodes colon-separated hex data and writes it to a file.
func writeHexDataToFile(path string, hexData string) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	defer file.Close()

	writer := bufio.NewWriterSize(file, 64*1024)

	cleaned := strings.ReplaceAll(hexData, ":", "")
	reader := strings.NewReader(cleaned)

	hexBuf := make([]byte, 64*1024)
	decodeBuf := make([]byte, 32*1024)

	for {
		n, readErr := reader.Read(hexBuf)
		if n == 0 {
			break
		}

		// Ensure even number of hex chars
		if n%2 != 0 {
			n--
			reader.Seek(-1, io.SeekCurrent)
		}

		decoded, decodeErr := hex.Decode(decodeBuf, hexBuf[:n])
		if decodeErr != nil {
			return fmt.Errorf("hex decode: %w", decodeErr)
		}

		if _, writeErr := writer.Write(decodeBuf[:decoded]); writeErr != nil {
			return fmt.Errorf("write: %w", writeErr)
		}

		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return fmt.Errorf("read: %w", readErr)
		}
	}

	return writer.Flush()
}
