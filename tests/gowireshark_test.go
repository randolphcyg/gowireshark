package tests

import (
	"testing"
	"time"

	"github.com/randolphcyg/gowireshark"
	"github.com/stretchr/testify/assert"
)

const inputFilepath = "../pcaps/mysql.pcapng"

func TestEpanVersion(t *testing.T) {
	t.Log(gowireshark.EpanVersion())
}

func TestEpanPluginsSupported(t *testing.T) {
	assert.Equal(t, 0, gowireshark.EpanPluginsSupported())
}

func TestDissectPrintFirstFrame(t *testing.T) {
	err := gowireshark.DissectPrintFirstFrame(inputFilepath)
	if err != nil {
		t.Fatal(err)
	}
}

func TestDissectPrintAllFrame(t *testing.T) {
	err := gowireshark.DissectPrintAllFrame(inputFilepath)
	if err != nil {
		t.Fatal(err)
	}
}

func TestDissectPrintFirstSeveralFrame(t *testing.T) {
	err := gowireshark.DissectPrintFirstSeveralFrame(inputFilepath, 5)
	if err != nil {
		t.Fatal(err)
	}
}

func TestDissectPrintSpecificFrame(t *testing.T) {
	err := gowireshark.DissectPrintSpecificFrame(inputFilepath, 70)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCapFileMulSeq(t *testing.T) {
	t.Log("@@@@@@@ 11111 @@@@@@")
	err := gowireshark.DissectPrintSpecificFrame(inputFilepath, 65)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("$$$$$$ 22222 $$$$$$$")
	err = gowireshark.DissectPrintSpecificFrame(inputFilepath, 71)
	if err != nil {
		t.Fatal(err)
	}
}

func TestDissectPrintSpecificFrameOutOfBounds(t *testing.T) {
	err := gowireshark.DissectPrintSpecificFrame(inputFilepath, 101)
	if err != nil {
		t.Log(err)
		assert.EqualError(t, err, "2: frame index is out of bounds")
	}
}

func TestGetSpecificFrameHexData(t *testing.T) {
	res, err := gowireshark.GetSpecificFrameHexData(inputFilepath, 65)
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
	// frameData
	frameData, err := gowireshark.GetSpecificFrameProtoTreeInJson(inputFilepath, 65, true, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("# WsIndex:", frameData.WsIndex)
	t.Log("# Offset:", frameData.Offset)
	t.Log("# Hex:", frameData.Hex)
	t.Log("# Ascii:", frameData.Ascii)

	// _ws.col
	colSrc := frameData.WsSource.Layers["_ws.col"]
	col, err := gowireshark.UnmarshalWsCol(colSrc)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("## col.number:", col.Num)

	// frame
	frameSrc := frameData.WsSource.Layers["frame"]
	frame, err := gowireshark.UnmarshalFrame(frameSrc)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("## frame.number:", frame.Number)

	// ip
	ipSrc := frameData.WsSource.Layers["ip"]
	if ipSrc == nil {
		return
	}
	ipContent, err := gowireshark.UnmarshalIp(ipSrc)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("## ip.src:", ipContent.Src)
	t.Log("## ip.dst:", ipContent.Dst)

	// http
	httpSrc := frameData.WsSource.Layers["http"]
	if httpSrc == nil {
		return
	}
	httpContent, err := gowireshark.UnmarshalHttp(httpSrc)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("## http.date:", httpContent.Date)
}

func TestGetAllFrameProtoTreeInJson(t *testing.T) {
	res, err := gowireshark.GetAllFrameProtoTreeInJson(inputFilepath, true, false)
	if err != nil {
		t.Fatal(err)
	}

	for _, frameData := range res {
		colSrc := frameData.WsSource.Layers["_ws.col"]
		col, err := gowireshark.UnmarshalWsCol(colSrc)
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

/*
Get interface device list, TODO but not return addresses of device (cause c logic error)
*/
func TestGetIfaceList(t *testing.T) {
	iFaces, err := gowireshark.GetIfaceList()
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
	status, err := gowireshark.GetIfaceNonblockStatus(ifaceName)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, ifaceName, "en7")
	assert.Equal(t, status, false)
}

func TestSetIfaceNonblockStatus(t *testing.T) {
	ifaceName := "en7"
	status, err := gowireshark.SetIfaceNonblockStatus(ifaceName, true)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, ifaceName, "en7")
	assert.Equal(t, status, true)
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
	timeout := 20

	// DissectResChans put pkg dissect result struct into go pipe
	gowireshark.DissectResChans[ifName] = make(chan gowireshark.FrameDissectRes, 100)

	// user read unmarshal data from go channel
	go func() {
		for {
			select {
			case frameData := <-gowireshark.DissectResChans[ifName]:
				colSrc := frameData.WsSource.Layers["_ws.col"]
				col, err := gowireshark.UnmarshalWsCol(colSrc)
				if err != nil {
					t.Error(err)
				}

				frameSrc := frameData.WsSource.Layers["frame"]
				frame, err := gowireshark.UnmarshalFrame(frameSrc)
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
			default:
			}
		}
	}()

	go func() {
		t.Log("Simulate manual stop real-time packet capture!")
		time.Sleep(time.Second * 2)
		err := gowireshark.StopDissectPktLive(ifName)
		if err != nil {
			t.Error(err)
			return
		}
		t.Log("############ stop capture successfully! ##############")
	}()

	// start c client, capture and dissect packet
	err := gowireshark.DissectPktLive(ifName, filter, pktNum, promisc, timeout)
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
	timeout := 20

	// DissectResChans put pkg dissect result struct into go pipe
	gowireshark.DissectResChans[ifName] = make(chan gowireshark.FrameDissectRes, 100)

	// user read unmarshal data from go channel
	go func() {
		for {
			select {
			case frameData := <-gowireshark.DissectResChans[ifName]:
				colSrc := frameData.WsSource.Layers["_ws.col"]
				col, err := gowireshark.UnmarshalWsCol(colSrc)
				if err != nil {
					t.Error(err)
				}

				frameSrc := frameData.WsSource.Layers["frame"]
				frame, err := gowireshark.UnmarshalFrame(frameSrc)
				if err != nil {
					t.Error(err)
				}

				t.Log("# Frame index:", frame.Number, "===========================")
				t.Log("## Offset:", frameData.Offset)
				t.Log("## Hex:", frameData.Hex)
				t.Log("## Ascii:", frameData.Ascii)

				t.Log("【layer frame】:", frame)
				t.Log("【layer _ws.col】:", col)
			default:
			}
		}
	}()

	// start c client, capture and dissect packet
	err := gowireshark.DissectPktLive(ifName, filter, pktNum, promisc, timeout)
	if err != nil {
		t.Fatal(err)
	}
}
