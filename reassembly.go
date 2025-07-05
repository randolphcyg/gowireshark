package gowireshark

import "C"
import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"sort"
	"sync"

	"github.com/bytedance/sonic"
	"github.com/pkg/errors"
)

// 文件签名（magic bytes）映射表
var fileSignatures = map[string][]byte{
	"png":  {0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a},
	"jpg":  {0xff, 0xd8, 0xff},
	"jpeg": {0xff, 0xd8, 0xff},
	"gif":  {0x47, 0x49, 0x46, 0x38, 0x39, 0x61},
	"pdf":  {0x25, 0x50, 0x44, 0x46},
	"zip":  {0x50, 0x4b, 0x03, 0x04},
	"tar":  {0x75, 0x73, 0x74, 0x61, 0x72},
	"rar":  {0x52, 0x61, 0x72, 0x21},
	"mp3":  {0x49, 0x44, 0x33},
	"txt":  {0x74, 0x65, 0x78, 0x74},
	"bmp":  {0x42, 0x4d},
	"xml":  {0x3c, 0x3f, 0x78, 0x6d, 0x6c},
	"exe":  {0x4d, 0x5a}, // MZ header for EXE files (DOS .exe and PE files)
}

// guessFileType 根据文件的 magic bytes 来推测文件类型
func guessFileType(data []byte) (string, string, error) {
	if len(data) < 2 {
		return "", "", fmt.Errorf("data is too short to determine file type")
	}

	// 检查每个已知的文件类型的签名
	for ext, signature := range fileSignatures {
		if bytes.HasPrefix(data, signature) {
			return ext, "." + ext, nil
		}
	}

	return "", "", fmt.Errorf("unknown file type")
}

type Packet struct {
	StreamID  uint32  `json:"stream_id"`
	PacketID  uint32  `json:"packet_id"`
	Src       string  `json:"src"`
	Dst       string  `json:"dst"`
	Timestamp float64 `json:"timestamp"`
	Data      string  `json:"data"`
	RawData   []byte
}

var TcpStreams = make(map[uint32][]Packet)
var mux sync.Mutex

//export GetTcpTapDataCallback
func GetTcpTapDataCallback(data *C.char, length C.int) {
	if data == nil || length <= 0 {
		return
	}

	packet, err := ParseTcpStream(C.GoStringN(data, length))
	if err != nil {
		fmt.Println("Error unmarshalling TCP stream:", err)
		return
	}

	// 使用锁保证 TcpStreams 是线程安全的
	mux.Lock()
	defer mux.Unlock()

	// 将流数据存储到 TcpStreams
	TcpStreams[packet.StreamID] = append(TcpStreams[packet.StreamID], *packet)
}

func ParseTcpStream(src string) (packet *Packet, err error) {
	if src == "" {
		return nil, errors.New("empty input data")
	}

	err = sonic.Unmarshal([]byte(src), &packet)
	if err != nil {
		return nil, ErrParseTcpStream
	}

	if len(packet.Data) > 0 {
		decodedData, decodeErr := base64.StdEncoding.DecodeString(packet.Data)
		if decodeErr != nil {
			return nil, fmt.Errorf("error decoding Base64 data: %v", decodeErr)
		}
		packet.RawData = decodedData // Replace the Base64 string with the raw byte data
	}

	return packet, nil
}

func SaveToFile(filename string, streamID uint32) error {
	mux.Lock()
	defer mux.Unlock()

	packets, exists := TcpStreams[streamID]
	if !exists {
		return fmt.Errorf("no packets found for stream ID %d", streamID)
	}

	// Sort packets by PacketID to ensure they are in the correct order
	sort.Slice(packets, func(i, j int) bool {
		return packets[i].PacketID < packets[j].PacketID
	})

	// 生成文件名并推测文件扩展名

	//fmt.Println(packets[0])

	ext := ".bin" // 默认扩展名
	if len(packets) > 0 {
		// 推测文件类型
		_, fileExt, err := guessFileType(packets[0].RawData)
		if err == nil {
			ext = fileExt
		} else {
			fmt.Println("Error guessing file type:", err)
		}
	}

	// 使用推测的扩展名生成文件名
	finalFilename := fmt.Sprintf("%s_%d%s", filename, streamID, ext)

	file, err := os.Create(finalFilename)
	if err != nil {
		return err
	}
	defer file.Close()

	for _, packet := range packets {
		if _, err := file.Write(packet.RawData); err != nil {
			return err
		}
	}

	fmt.Printf("File saved as %s\n", finalFilename)
	return nil
}
