package gowireshark

/*
#cgo pkg-config: glib-2.0
#cgo LDFLAGS: -Wl,-rpath,${SRCDIR}/libs
#cgo LDFLAGS: -L${SRCDIR}/libs -lwiretap -lwsutil -lwireshark -lpcap
#cgo CFLAGS: -I${SRCDIR}/include
#cgo CFLAGS: -I${SRCDIR}/include/wireshark
#cgo CFLAGS: -I${SRCDIR}/include/libpcap

#include "lib.h"
#include "online.h"
#include "offline.h"
*/
import "C"
import (
	"encoding/json"
	"log/slog"
	"os"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/pkg/errors"
)

var (
	ErrFileNotFound    = errors.New("cannot open file, no such file")
	ErrReadFile        = errors.New("occur error when read file ")
	ErrFromCLogic      = errors.New("run c logic occur error")
	ErrParseDissectRes = errors.New("fail to parse DissectRes")
	ErrFrameIsBlank    = errors.New("frame data is blank")
)

// DissectResChans dissect result chan map
var DissectResChans = make(map[string]chan FrameDissectRes)

var EpanMutex = &sync.Mutex{}

// Init policies、WTAP mod、EPAN mod.
func init() {
	initEnvRes := C.init_env()
	if initEnvRes == 0 {
		panic("fail to init env")
	}
}

// isFileExist check if the file path exists
func isFileExist(path string) bool {
	_, err := os.Lstat(path)
	return !os.IsNotExist(err)
}

// CChar2GoStr C string -> Go string
func CChar2GoStr(src *C.char) string {
	return C.GoStringN(src, C.int(C.strlen(src)))
}

// EpanVersion get epan module's version
func EpanVersion() string {
	return C.GoString((*C.char)(C.epan_get_version()))
}

// EpanPluginsSupported
//
//	@Description:
//	@return int: 0 if plugins can be loaded for all of libwireshark (tap, dissector, epan);
//	1 if plugins are not supported by the platform;
//	-1 if plugins were disabled in the build configuration.
func EpanPluginsSupported() int {
	return int(C.epan_plugins_supported())
}

// initCapFile Init capture file only once for each pcap file
func initCapFile(inputFilepath string, opts ...Option) (conf *Conf, err error) {
	if !isFileExist(inputFilepath) {
		err = errors.Wrap(ErrFileNotFound, inputFilepath)
		return
	}

	conf = NewConfig(opts...)
	errNo := C.init_cf(C.CString(inputFilepath), C.CString(HandleTlsConf(conf)))
	if errNo != 0 {
		err = errors.Wrap(ErrReadFile, strconv.Itoa(int(errNo)))
		return
	}

	return
}

// DissectPrintAllFrame Dissect and print all frames
func DissectPrintAllFrame(inputFilepath string, opts ...Option) (err error) {
	EpanMutex.Lock()
	defer EpanMutex.Unlock()

	_, err = initCapFile(inputFilepath, opts...)
	if err != nil {
		return
	}

	C.print_all_frame()

	return
}

// HexData hex data
type HexData struct {
	Offset []string `json:"offset"`
	Hex    []string `json:"hex"`
	Ascii  []string `json:"ascii"`
}

// UnmarshalHexData Unmarshal hex data dissect result
func UnmarshalHexData(src string) (res HexData, err error) {
	err = json.Unmarshal([]byte(src), &res)
	if err != nil {
		return HexData{}, err
	}

	return
}

// GetSpecificFrameHexData Get hex data of specific frame
func GetSpecificFrameHexData(inputFilepath string, num int, opts ...Option) (hexData HexData, err error) {
	EpanMutex.Lock()
	defer EpanMutex.Unlock()

	_, err = initCapFile(inputFilepath, opts...)
	if err != nil {
		return
	}

	// get specific frame hex data in json format by c
	srcHex := C.get_specific_frame_hex_data(C.int(num))
	if srcHex != nil {
		if C.strlen(srcHex) == 0 { // loop ends
			return
		}
	}

	// unmarshal dissect result
	hexData, err = UnmarshalHexData(CChar2GoStr(srcHex))
	if err != nil {
		slog.Warn("UnmarshalHexData:", "UnmarshalDissectResult", err)
		return
	}

	return
}

// UnmarshalDissectResult Unmarshal dissect result with concurrency
func UnmarshalDissectResult(src string) (frameRes *FrameDissectRes, err error) {
	err = json.Unmarshal([]byte(src), &frameRes)
	if err != nil {
		return nil, ErrParseDissectRes
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	var errorsList []error

	// handle each layer
	handleLayer := func(layerFunc func() (any, error), setLayerFunc func(any)) {
		defer wg.Done()
		layer, err := layerFunc()
		if err != nil && !errors.Is(err, ErrLayerNotFound) { // ignore if layer not found
			errorsList = append(errorsList, err)
		}
		if layer != nil {
			mu.Lock()
			setLayerFunc(layer) // update BaseLayers
			mu.Unlock()
		}
	}

	wg.Add(7)

	go handleLayer(frameRes.WsSource.Layers.WsCol, func(layer any) {
		frameRes.BaseLayers.WsCol = layer.(*WsCol)
	})

	go handleLayer(frameRes.WsSource.Layers.Frame, func(layer any) {
		frameRes.BaseLayers.Frame = layer.(*Frame)
	})

	go handleLayer(frameRes.WsSource.Layers.Ip, func(layer any) {
		frameRes.BaseLayers.Ip = layer.(*Ip)
	})

	go handleLayer(frameRes.WsSource.Layers.Udp, func(layer any) {
		frameRes.BaseLayers.Udp = layer.(*Udp)
	})

	go handleLayer(frameRes.WsSource.Layers.Tcp, func(layer any) {
		frameRes.BaseLayers.Tcp = layer.(*Tcp)
	})

	go handleLayer(frameRes.WsSource.Layers.Http, func(layer any) {
		frameRes.BaseLayers.Http = layer.(*Http)
	})

	go handleLayer(frameRes.WsSource.Layers.Dns, func(layer any) {
		frameRes.BaseLayers.Dns = layer.(*Dns)
	})

	wg.Wait()

	// Summarize all errors of a frame
	if len(errorsList) > 0 {
		return frameRes, errors.Errorf("frame:%d:%v", frameRes.BaseLayers.Frame.Number, errorsList)
	}

	return frameRes, nil
}

// GetSpecificFrameProtoTreeInJson
//
//	@Description: dissect specific frame of the pcap file and return go json
//	@param inputFilepath: Pcap src file path
//	@param num: The max frame index value of the JSON results
//	@return res: Contains specific frame's JSON dissect result
func GetSpecificFrameProtoTreeInJson(inputFilepath string, num int, opts ...Option) (frameDissectRes *FrameDissectRes, err error) {
	EpanMutex.Lock()
	defer EpanMutex.Unlock()

	conf, err := initCapFile(inputFilepath, opts...)
	if err != nil {
		return
	}

	descriptive := 0
	if conf.Descriptive {
		descriptive = 1
	}

	printCJson := 0
	if conf.PrintCJson {
		printCJson = 1
	}

	counter := 0
	for {
		counter++
		if counter < num && num != counter {
			continue
		}

		// get proto dissect result in json format by c
		srcFrame := C.proto_tree_in_json(C.int(counter), C.int(descriptive), C.int(printCJson))
		if srcFrame != nil {
			if C.strlen(srcFrame) == 0 {
				return frameDissectRes, ErrFrameIsBlank
			}
		}

		// unmarshal dissect result
		frameDissectRes, err = UnmarshalDissectResult(CChar2GoStr(srcFrame))
		if err != nil {
			slog.Warn("GetSpecificFrameProtoTreeInJson:", "UnmarshalDissectResult", err)
			return
		}

		return
	}
}

func removeNegativeAndZero(nums []int) []int {
	var result []int
	for _, num := range nums {
		if num > 0 {
			result = append(result, num)
		}
	}
	return result
}

// GetSeveralFrameProtoTreeInJson
//
//	@Description: dissect several specific frame of the pcap file and return go json
//	@param inputFilepath: Pcap src file path
//	@param nums: The frame number that needs to be output
//	@return res: Contains specific frame's JSON dissect result
func GetSeveralFrameProtoTreeInJson(inputFilepath string, nums []int, opts ...Option) (res []*FrameDissectRes, err error) {
	EpanMutex.Lock()
	defer EpanMutex.Unlock()

	conf, err := initCapFile(inputFilepath, opts...)
	if err != nil {
		return
	}

	descriptive := 0
	if conf.Descriptive {
		descriptive = 1
	}

	printCJson := 0
	if conf.PrintCJson {
		printCJson = 1
	}

	nums = removeNegativeAndZero(nums)
	// Must sort from smallest to largest
	slices.Sort(nums)

	for _, num := range nums {
		// get proto dissect result in json format by c
		srcFrame := C.proto_tree_in_json(C.int(num), C.int(descriptive), C.int(printCJson))
		if srcFrame != nil {
			if C.strlen(srcFrame) == 0 {
				continue
			}
		}

		// unmarshal dissect result
		singleFrame, err := UnmarshalDissectResult(CChar2GoStr(srcFrame))
		if err != nil {
			slog.Warn("GetSeveralFrameProtoTreeInJson:", "UnmarshalDissectResult", err)
		}

		res = append(res, singleFrame)
	}

	return
}

// GetAllFrameProtoTreeInJson
//
//	@Description: dissect the pcap file and return go json
//	@param inputFilepath: Pcap src file path
//	@return res: Contains all frame's JSON dissect result
func GetAllFrameProtoTreeInJson(inputFilepath string, opts ...Option) (res []*FrameDissectRes, err error) {
	EpanMutex.Lock()
	defer EpanMutex.Unlock()
	conf, err := initCapFile(inputFilepath, opts...)

	if err != nil {
		return nil, err
	}

	descriptive := 0
	if conf.Descriptive {
		descriptive = 1
	}

	printCJson := 0
	if conf.PrintCJson {
		printCJson = 1
	}

	start := time.Now()

	// work queue & result queue
	frameChannel := make(chan string, 100)
	resultChannel := make(chan *FrameDissectRes, 100)
	errorChannel := make(chan error, 10)

	var parseWG sync.WaitGroup

	var allErrors []error
	var errorsMutex sync.Mutex

	// startup Go JSON parser working pool
	numWorkers := 8 // parse worker num
	parseWG.Add(numWorkers)
	for i := 0; i < numWorkers; i++ {
		go func() {
			defer parseWG.Done()
			for srcFrame := range frameChannel {
				singleFrame, err := UnmarshalDissectResult(srcFrame)
				if err != nil {
					if conf.IgnoreError {
						continue
					}
					errorsMutex.Lock()
					allErrors = append(allErrors, err)
					errorsMutex.Unlock()
					errorChannel <- err
					return
				}

				resultChannel <- singleFrame
			}
		}()
	}

	// call C function
	go func() {
		defer close(frameChannel)
		counter := 1
		for {
			srcFrame := C.proto_tree_in_json(C.int(counter), C.int(descriptive), C.int(printCJson))
			if srcFrame == nil || C.strlen(srcFrame) == 0 { // end
				break
			}

			frameChannel <- CChar2GoStr(srcFrame)
			counter++
		}
	}()

	go func() {
		parseWG.Wait()
		close(resultChannel)
		close(errorChannel)
	}()

	for frame := range resultChannel {
		res = append(res, frame)
	}

	if !conf.IgnoreError {
		for err := range errorChannel {
			errorsMutex.Lock()
			allErrors = append(allErrors, err)
			errorsMutex.Unlock()
		}

		if len(allErrors) > 0 {
			slog.Info("Error Log output:", "PCAP_FILE", inputFilepath)
			for _, e := range allErrors {
				slog.Warn("GetAllFrameProtoTreeInJson:", "UnmarshalDissectResult", e)
			}
			slog.Info("Error Log end:", "PCAP_FILE", inputFilepath)
		}
	}

	if conf.Debug {
		slog.Info("Dissect end:", "ELAPSED", time.Since(start), "PCAP_FILE", inputFilepath)
	}

	return res, nil
}
