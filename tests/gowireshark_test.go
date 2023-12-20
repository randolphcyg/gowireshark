package tests

import (
	"encoding/json"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/randolphcyg/gowireshark"
)

const inputFilepath = "../pcaps/mysql.pcapng"

func TestEpanVersion(t *testing.T) {
	fmt.Println(gowireshark.EpanVersion())
}

func TestEpanPluginsSupported(t *testing.T) {
	fmt.Println(gowireshark.EpanPluginsSupported())
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
	var err error

	fmt.Println("@@@@@@@@@@@@@")
	err = gowireshark.DissectPrintSpecificFrame(inputFilepath, 65)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("$$$$$$$$$$$$$")
	err = gowireshark.DissectPrintSpecificFrame(inputFilepath, 71)
	if err != nil {
		t.Fatal(err)
	}
}

/*
RESULT: none
*/
func TestDissectPrintSpecificFrameOutOfBounds(t *testing.T) {
	err := gowireshark.DissectPrintSpecificFrame(inputFilepath, 101)
	if err != nil {
		t.Fatal(err)
	}
}

func TestGetSpecificFrameHexData(t *testing.T) {
	res, err := gowireshark.GetSpecificFrameHexData(inputFilepath, 65)
	if err != nil {
		t.Fatal(err)
	}

	for i, item := range res.Offset {
		fmt.Println(i, item)
	}
	for i, item := range res.Hex {
		fmt.Println(i, item)
	}
	for i, item := range res.Ascii {
		fmt.Println(i, item)
	}
}

func TestGetSpecificFrameProtoTreeInJson(t *testing.T) {
	res, err := gowireshark.GetSpecificFrameProtoTreeInJson(inputFilepath, 65, false, true)
	if err != nil {
		t.Fatal(err)
	}

	for idx, frameData := range res {
		colSrc := frameData.WsSource.Layers["_ws.col"]
		col, err := gowireshark.UnmarshalWsCol(colSrc)
		if err != nil {
			t.Fatal(err)
		}

		frameSrc := frameData.WsSource.Layers["frame"]
		frame, err := gowireshark.UnmarshalFrame(frameSrc)
		if err != nil {
			t.Fatal(err)
		}

		fmt.Println("# Frame index:", col.Num)
		fmt.Println("## WsIndex:", frameData.WsIndex)
		fmt.Println("## Offset:", frameData.Offset)
		fmt.Println("## Hex:", frameData.Hex)
		fmt.Println("## Ascii:", frameData.Ascii)

		fmt.Println(idx, "【layer _ws.col】:", col)
		fmt.Println(idx, "【layer frame】:", frame)
	}
}

func TestGetAllFrameProtoTreeInJson(t *testing.T) {
	res, err := gowireshark.GetAllFrameProtoTreeInJson(inputFilepath, true, true)
	if err != nil {
		t.Fatal(err)
	}

	// read frame from channel
	for frame := range res {
		fmt.Println("## Frame:", frame)
		fmt.Println("======================================================")
	}
}

/*
Get interface device list, TODO but not return addresses of device (cause c logic error)
Result:
bluetooth-monitor Bluetooth Linux Monitor 56
nflog Linux netfilter log (NFLOG) interface 48
nfqueue Linux netfilter queue (NFQUEUE) interface 48
dbus-system D-Bus system bus 48
dbus-session D-Bus session bus 48
ens33  22
any Pseudo-device that captures on all interfaces 54
lo  55
*/
func TestGetIfaceList(t *testing.T) {
	iFaces, err := gowireshark.GetIfaceList()
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range iFaces {
		fmt.Println(k, v.Description, v.Flags)
	}
}

/*
Get interface device nonblock status, default is false
Result:
device: ens33  nonblock status: false
*/
func TestGetIfaceNonblockStatus(t *testing.T) {
	ifaceName := "ens33"
	status, err := gowireshark.GetIfaceNonblockStatus(ifaceName)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("device:", ifaceName, " nonblock status:", status)
}

func TestSetIfaceNonblockStatus(t *testing.T) {
	ifaceName := "ens33"
	status, err := gowireshark.SetIfaceNonblockStatus(ifaceName, true)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("device:", ifaceName, "after set, now nonblock status is:", status)
}

/*
Test infinite loop fetching and parsing packets.
Set the num parameter of the DissectPktLive function to -1
to process packets in an infinite loop.
*/
func TestDissectPktLiveInfinite(t *testing.T) {
	sockServerPath := "/tmp/gsocket"
	// sockBuffSize The maximum length of packet detail data transmitted by the Unix domain socket;
	// Beyond this length will be safely truncated at c; The truncated data will not be properly deserialized into a golang struct.
	sockBuffSize := 655350
	ifName := "ens33"
	filter := "tcp and port 3306"
	pktNum := -1
	promisc := 1
	timeout := 20
	livePkgCount := 0

	// UnixListener socket server listener
	var UnixListener *net.UnixConn

	// PkgDetailLiveChan put pkg detail struct into go pipe
	var PkgDetailLiveChan = make(chan gowireshark.FrameDissectRes, 1000)

	// socket server: start socket server and wait data to come
	err := gowireshark.RunSock(sockServerPath, sockBuffSize, UnixListener, PkgDetailLiveChan)
	if err != nil {
		t.Fatal(err)
	}

	// user read unmarshal data from go channel
	go func() {
		for {
			select {
			case pkg := <-PkgDetailLiveChan:
				livePkgCount++
				pkgByte, _ := json.Marshal(pkg)
				fmt.Printf("Processed pkg:【%d】pkg len:【%d】\n", livePkgCount, len(pkgByte))
				//fmt.Println(pkg)
			default:
			}
		}
	}()

	// start socket client, capture and dissect packet.
	err = gowireshark.DissectPktLive(ifName, filter, sockServerPath, pktNum, promisc, timeout)
	if err != nil {
		t.Fatal(err)
	}

	select {}
}

/*
Set the num parameter of the DissectPktLive function to a specific num like 20
to process packets in a limited loop.
*/
func TestDissectPktLiveSpecificNum(t *testing.T) {
	sockServerPath := "/tmp/gsocket"
	// sockBuffSize The maximum length of packet detail data transmitted by the Unix domain socket;
	// Beyond this length will be safely truncated at c; The truncated data will not be properly deserialized into a golang struct.
	sockBuffSize := 655350
	ifName := "en0"
	filter := "tcp and port 3306"
	pktNum := 20
	promisc := 1
	timeout := 20
	livePkgCount := 0

	// UnixListener socket server listener
	var UnixListener *net.UnixConn

	// PkgDetailLiveChan put pkg detail struct into go pipe
	var PkgDetailLiveChan = make(chan gowireshark.FrameDissectRes, 1000)

	// socket server: start socket server and wait data to come
	err := gowireshark.RunSock(sockServerPath, sockBuffSize, UnixListener, PkgDetailLiveChan)
	if err != nil {
		t.Fatal(err)
	}

	// user read unmarshal data from go channel
	go func() {
		for {
			select {
			case pkg := <-PkgDetailLiveChan:
				livePkgCount++
				pkgByte, _ := json.Marshal(pkg)
				fmt.Printf("Processed pkg:【%d】pkg len:【%d】\n", livePkgCount, len(pkgByte))
				fmt.Println(pkg)
			default:
			}
		}
	}()

	// start socket client, capture and dissect packet.
	err = gowireshark.DissectPktLive(ifName, filter, sockServerPath, pktNum, promisc, timeout)
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(time.Second)
}

func TestStopDissectPktLive(t *testing.T) {
	sockServerPath := "/tmp/gsocket"
	ifName := "ens33"
	filter := "tcp and port 3306"
	// sockBuffSize The maximum length of packet detail data transmitted by the Unix domain socket;
	// Beyond this length will be safely truncated at c; The truncated data will not be properly deserialized into a golang struct.
	sockBuffSize := 655350
	pktNum := -1
	promisc := 1
	timeout := 20
	livePkgCount := 0

	// UnixListener socket server listener
	var UnixListener *net.UnixConn

	// PkgDetailLiveChan put pkg detail struct into go pipe
	var PkgDetailLiveChan = make(chan gowireshark.FrameDissectRes, 1000)

	// socket server: start socket server and wait data to come
	err := gowireshark.RunSock(sockServerPath, sockBuffSize, UnixListener, PkgDetailLiveChan)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("socket server started!")

	// user read unmarshal data from go channel
	go func() {
		for {
			select {
			case pkg := <-PkgDetailLiveChan:
				//time.Sleep(time.Millisecond * 200)
				livePkgCount++
				pkgByte, _ := json.Marshal(pkg)
				fmt.Printf("Processed pkg:【%d】pkg len:【%d】\n", livePkgCount, len(pkgByte))
			default:
			}
		}

	}()

	go func() {
		fmt.Println("Simulate manual stop real-time packet capture!")
		time.Sleep(time.Second * 2)
		err := gowireshark.StopDissectPktLive(ifName)
		if err != nil {
			t.Error(err)
			return
		}
		fmt.Println("############ stop capture successfully! ##############")
	}()

	fmt.Println("start c client, start capture function")
	// start socket client, capture and dissect packet.
	err = gowireshark.DissectPktLive(ifName, filter, sockServerPath, pktNum, promisc, timeout)
	if err != nil {
		t.Fatal(err)
	}

	select {}
}
