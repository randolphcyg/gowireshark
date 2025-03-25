package gowireshark

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
)

var (
	//go:embed mime_types.txt
	mimeTypesFile embed.FS

	validExtensions = make(map[string]bool)
	mu              sync.RWMutex

	genFilenameLock sync.Mutex

	ExtractFileDir = "" // extract file save dir
)

func init() {
	data, err := mimeTypesFile.ReadFile("mime_types.txt")
	if err != nil {
		slog.Warn("Error:", "Failed to read embedded file", err)
		return
	}

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) == 2 {
			ext, typ := parts[0], parts[1]
			// Add to mime library
			err := mime.AddExtensionType(ext, typ)
			if err != nil {
				slog.Warn("Error:", "Failed to add extension type", err)
			}
			// Add to valid extensions map
			mu.Lock()
			validExtensions[ext] = true
			mu.Unlock()
		} else {
			slog.Warn("Error:", "Invalid line in mime types file", line)
		}
	}

	if err := scanner.Err(); err != nil {
		slog.Warn("Error:", "Error reading mime types file", err)
	}
}

// IsValidFileExtension checks if a file has a valid extension
func IsValidFileExtension(filename string) bool {
	ext := strings.ToLower(strings.TrimSpace(filepath.Ext(filename)))
	mu.RLock()
	defer mu.RUnlock()
	return validExtensions[ext]
}

// GenerateUniqueFilenameWithIncrement if file exist, add auto-increment num
func GenerateUniqueFilenameWithIncrement(filename string) string {
	genFilenameLock.Lock()
	defer genFilenameLock.Unlock()

	ext := filepath.Ext(filename)
	base := strings.TrimSuffix(filename, ext)
	counter := 1

	for {
		path := filepath.Join(ExtractFileDir, filename)
		if !IsFileExist(path) {
			break
		}
		filename = fmt.Sprintf("%s(%d)%s", base, counter, ext)
		counter++
	}

	return filepath.Join(ExtractFileDir, filename)
}

// UrlStringDecode Decode URL-encoded strings into raw text
func UrlStringDecode(encoded string) (string, error) {
	return url.QueryUnescape(encoded)
}

func ExtractHttpFilename(http *Http) (string, error) {
	if http.ResponseLine == nil || http.FileData == "" {
		return "", errors.New("no file data")
	}

	if http.ResponseCode == "404" || http.ResponseCode == "301" {
		return "", errors.New("ignore 404 or 301")
	}

	filename := "tmp"
	includeFilename := false

	// Content-Disposition
	for _, line := range *http.ResponseLine {
		if strings.Contains(strings.ToLower(line), "filename=") {
			reg := regexp.MustCompile(`(?i)filename="?([^"]+)"?`)
			if match := reg.FindStringSubmatch(line); len(match) > 1 {
				filename = match[1]
				includeFilename = true
				break
			}
		} else if strings.Contains(strings.ToLower(line), "filename*=utf-8''") {
			reg := regexp.MustCompile(`(?i)filename\*=utf-8''([^;,\r\n]+)`)
			if match := reg.FindStringSubmatch(line); len(match) > 1 {
				if decoded, err := UrlStringDecode(match[1]); err == nil {
					filename = decoded
					includeFilename = true
					break
				} else {
					slog.Warn("Error:", "Failed to decode URL-encoded filename", err)
				}
			}
		}
	}

	// URL
	if !includeFilename {
		p := http.ResponseUrl
		if p == "" {
			p = http.RequestUri
		}
		filename = filepath.Base(p)
		filename, _ = url.QueryUnescape(strings.Split(filename, "?")[0])
	}

	// check filename validation
	if filename == "" || filename == "/" || !IsValidFileExtension(filename) {
		filename = "tmp"
	}

	// speculate on file types and generate file extensions
	if filepath.Ext(filename) == "" && http.ContentType != "" {
		if http.ContentType != "" {
			extensions, _ := mime.ExtensionsByType(http.ContentType)
			if len(extensions) > 0 {
				filename += extensions[0]
			}
		}
	}

	// Make sure the filename is unique and add an extension
	path := filepath.Join(ExtractFileDir, filename)
	if IsFileExist(path) {
		path = GenerateUniqueFilenameWithIncrement(filename)
	}

	return path, nil
}

func ExtractHttpFile(httpList []*Http) ([]string, error) {
	paths := make([]string, 0)
	for _, http := range httpList {
		if http == nil {
			continue
		}

		path, err := ExtractHttpFilename(http)
		if err != nil {
			continue
		}

		file, err := os.Create(path)
		if err != nil {
			slog.Warn("Error:", "Failed to create file", err)
			continue
		}
		defer file.Close()

		decoder := strings.NewReader(strings.ReplaceAll(http.FileData, ":", ""))
		buffer := make([]byte, 1024*1024) // 1MB buffer

		for {
			n, err := decoder.Read(buffer)
			if err != nil && err != io.EOF {
				slog.Warn("Error:", "Error reading file", err)
				break
			}

			if n == 0 {
				break
			}

			decodedData := make([]byte, hex.DecodedLen(n))
			_, decodeErr := hex.Decode(decodedData, buffer[:n])
			if decodeErr != nil {
				slog.Warn("Error:", "Error decoding file", err)
				break
			}

			if _, writeErr := file.Write(decodedData); writeErr != nil {
				slog.Warn("Error:", "Error writing file", err)
				break
			}
		}
		paths = append(paths, path)
	}

	return paths, nil
}
