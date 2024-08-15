package gowireshark

import (
	"sync"
	"testing"
	"time"
)

const inputFilepath = "./pcaps/mysql.pcapng"

func TestEpanVersion(t *testing.T) {
	t.Log(EpanVersion())
}

func TestEpanPluginsSupported(t *testing.T) {
	t.Logf("expected 0, got %d", EpanPluginsSupported())
}

func TestDissectPrintAllFrame(t *testing.T) {
	err := DissectPrintAllFrame(inputFilepath)
	if err != nil {
		t.Fatal(err)
	}
}

func TestGetSpecificFrameHexData(t *testing.T) {
	res, err := GetSpecificFrameHexData(inputFilepath, 65)
	if err != nil {
		t.Fatal(err)
	}

	for i, item := range res.Offset {
		t.Log(i, item)
	}
	for i, item := range res.Hex {
		t.Log(i, item)
	}
	for i, item := range res.Ascii {
		t.Log(i, item)
	}
}

func TestGetSpecificFrameProtoTreeInJson(t *testing.T) {
	frameData, err := GetSpecificFrameProtoTreeInJson(inputFilepath, 65, true, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("# WsIndex:", frameData.WsIndex)
	t.Log("# Offset:", frameData.Offset)
	t.Log("# Hex:", frameData.Hex)
	t.Log("# Ascii:", frameData.Ascii)

	// _ws.col
	colSrc := frameData.WsSource.Layers["_ws.col"]
	col, err := UnmarshalWsCol(colSrc)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("## col.number:", col.Num)

	// frame
	frameSrc := frameData.WsSource.Layers["frame"]
	frame, err := UnmarshalFrame(frameSrc)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("## frame.number:", frame.Number)
	ti := TimeEpoch2Time(frame.TimeEpoch)
	t.Log("## frame.TimeEpoch:", ti)

	// ip
	ipSrc := frameData.WsSource.Layers["ip"]
	if ipSrc != nil {
		ipContent, err := UnmarshalIp(ipSrc)
		if err != nil {
			t.Fatal(err)
		}
		t.Log("## ip.src:", ipContent.Src)
		t.Log("## ip.dst:", ipContent.Dst)
	}

	// tcp
	tcpSrc := frameData.WsSource.Layers["tcp"]
	if ipSrc != nil {
		tcpContent, err := UnmarshalTcp(tcpSrc)
		if err != nil {
			t.Fatal(err)
		}
		t.Log("## tcp.srcport:", tcpContent.SrcPort)
	}

	// udp
	udpSrc := frameData.WsSource.Layers["udp"]
	if udpSrc != nil {
		udpContent, err := UnmarshalUdp(udpSrc)
		if err != nil {
			t.Fatal(err)
		}
		t.Log("## udp.srcport:", udpContent.SrcPort)
	}

	// http
	httpSrc := frameData.WsSource.Layers["http"]
	if httpSrc != nil {
		httpContent, err := UnmarshalHttp(httpSrc)
		if err != nil {
			t.Fatal(err)
		}
		t.Log("## http.date:", httpContent.Date)
	}

}

func TestGetSeveralFrameProtoTreeInJson(t *testing.T) {
	nums := []int{11, 5, 0, 1, -1, 13, 288}
	res, err := GetSeveralFrameProtoTreeInJson(inputFilepath, nums, true, false)
	if err != nil {
		t.Fatal(err)
	}

	// [1 5 11 13]
	for _, frameData := range res {
		layers := frameData.WsSource.Layers
		colSrc := layers["_ws.col"]
		col, err := UnmarshalWsCol(colSrc)
		if err != nil {
			t.Fatal(err)
		}

		t.Log("# Frame index:", col.Num, "===========================")
		t.Log("## WsIndex:", frameData.WsIndex)
		t.Log("## Offset:", frameData.Offset)
		t.Log("## Hex:", frameData.Hex)
		t.Log("## Ascii:", frameData.Ascii)
	}
}

func TestGetAllFrameProtoTreeInJson(t *testing.T) {
	res, err := GetAllFrameProtoTreeInJson(inputFilepath, true, false)
	if err != nil {
		t.Fatal(err)
	}

	for _, frameData := range res {
		colSrc := frameData.WsSource.Layers["_ws.col"]
		col, err := UnmarshalWsCol(colSrc)
		if err != nil {
			t.Fatal(err)
		}

		t.Log("# Frame index:", col.Num, "===========================")
		t.Log("## WsIndex:", frameData.WsIndex)
		t.Log("## Offset:", frameData.Offset)
		t.Log("## Hex:", frameData.Hex)
		t.Log("## Ascii:", frameData.Ascii)
	}
}

func TestGoroutineGetAllFrameProtoTreeInJson(t *testing.T) {
	var wg sync.WaitGroup
	numGoroutines := 100

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			res, err := GetAllFrameProtoTreeInJson(inputFilepath, true, false)
			if err != nil {
				t.Error(err)
			}
			t.Log(i, inputFilepath, " >>>> ", len(res))
		}(i)
	}

	wg.Wait()
}

/*
Get interface device list, TODO but not return addresses of device (cause c logic error)
*/
func TestGetIfaceList(t *testing.T) {
	iFaces, err := GetIfaceList()
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range iFaces {
		t.Log(k, v.Description, v.Flags)
	}
}

/*
Get interface device nonblock status, default is false
*/
func TestGetIfaceNonblockStatus(t *testing.T) {
	ifaceName := "en7"
	status, err := GetIfaceNonblockStatus(ifaceName)
	if err != nil {
		t.Fatal(err)
	}

	if status != false {
		t.Errorf("expected status false, got %v", status)
	}
}

func TestSetIfaceNonblockStatus(t *testing.T) {
	ifaceName := "en7"
	status, err := SetIfaceNonblockStatus(ifaceName, true)
	if err != nil {
		t.Fatal(err)
	}

	if status != true {
		t.Errorf("expected status true, got %v", status)
	}
}

/*
Test infinite loop capturing and Dissecting packets、stop capturing and Dissecting.
Set the num parameter of the DissectPktLive function to -1
to process packets in an infinite loop.
Stop capturing and Dissecting after 2 seconds
*/
func TestDissectPktLiveInfiniteAndStopCapturePkg(t *testing.T) {
	ifName := "en7"
	filter := ""
	pktNum := -1
	promisc := 1
	timeout := 5

	// DissectResChans put pkg dissect result struct into go pipe
	DissectResChans[ifName] = make(chan FrameDissectRes, 100)
	defer close(DissectResChans[ifName])

	// user read unmarshal data from go channel
	go func() {
		for frameData := range DissectResChans[ifName] {
			colSrc := frameData.WsSource.Layers["_ws.col"]
			col, err := UnmarshalWsCol(colSrc)
			if err != nil {
				t.Error(err)
			}

			frameSrc := frameData.WsSource.Layers["frame"]
			frame, err := UnmarshalFrame(frameSrc)
			if err != nil {
				t.Error(err)
			}

			t.Log("# Frame index:", col.Num, "===========================")
			t.Log("## WsIndex:", frameData.WsIndex)
			t.Log("## Offset:", frameData.Offset)
			t.Log("## Hex:", frameData.Hex)
			t.Log("## Ascii:", frameData.Ascii)

			t.Log("【layer _ws.col】:", col)
			t.Log("【layer frame】:", frame)
		}
	}()

	go func() {
		t.Log("Simulate manual stop real-time packet capture!")
		time.Sleep(time.Second * 2)
		err := StopDissectPktLive(ifName)
		if err != nil {
			t.Error(err)
			return
		}
		t.Log("############ stop capture successfully! ##############")
	}()

	// start c client, capture and dissect packet
	err := DissectPktLive(ifName, filter, pktNum, promisc, timeout)
	if err != nil {
		t.Fatal(err)
	}
}

/*
Set the num parameter of the DissectPktLive function to a specific num like 20
to process packets in a limited loop.
*/
func TestDissectPktLiveSpecificNum(t *testing.T) {
	ifName := "en7"
	filter := ""
	pktNum := 20
	promisc := 1
	timeout := 5

	var wg sync.WaitGroup
	defer wg.Wait()

	DissectResChans[ifName] = make(chan FrameDissectRes, 100)
	defer close(DissectResChans[ifName])

	wg.Add(1)

	go func() {
		defer wg.Done()
		for frameData := range DissectResChans[ifName] {
			colSrc := frameData.WsSource.Layers["_ws.col"]
			col, err := UnmarshalWsCol(colSrc)
			if err != nil {
				t.Error(err)
				continue
			}

			frameSrc := frameData.WsSource.Layers["frame"]
			frame, err := UnmarshalFrame(frameSrc)
			if err != nil {
				t.Error(err)
				continue
			}

			t.Log("# Frame index:", frame.Number, "===========================")
			t.Log("## Offset:", frameData.Offset)
			t.Log("## Hex:", frameData.Hex)
			t.Log("## Ascii:", frameData.Ascii)

			t.Log("【layer frame】:", frame)
			t.Log("【layer _ws.col】:", col)
		}
	}()

	// start c client, capture and dissect packet
	err := DissectPktLive(ifName, filter, pktNum, promisc, timeout)
	if err != nil {
		t.Fatal(err)
	}
}
