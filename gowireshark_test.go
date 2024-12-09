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
	frameData, err := GetSpecificFrameProtoTreeInJson(inputFilepath, 65,
		WithDescriptive(true), WithDebug(true))
	if err != nil {
		t.Fatal(err)
	}
	t.Log("# WsIndex:", frameData.WsIndex)
	t.Log("# Offset:", frameData.Offset)
	t.Log("# Hex:", frameData.Hex)
	t.Log("# Ascii:", frameData.Ascii)

	layers := Layers(frameData.WsSource.Layers)

	// _ws.col
	if colLayer, err := layers.WsCol(); err == nil {
		t.Log("## col.number:", colLayer.Num)
	} else {
		t.Error(err)
	}

	// frame
	if frameLayer, err := layers.Frame(); err == nil {
		t.Log("## frame.number:", frameLayer.Number)
		t.Log("## frame.TimeEpoch:", TimeEpoch2Time(frameLayer.TimeEpoch))
	} else {
		t.Error(err)
	}

	// ip
	if ipLayer, err := layers.Ip(); err == nil {
		t.Log("## ip.src:", ipLayer.Src)
		t.Log("## ip.dst:", ipLayer.Dst)
	} else {
		t.Error(err)
	}

	// udp
	if udpLayer, err := layers.Udp(); err == nil {
		t.Log("## udp.srcport:", udpLayer.SrcPort)
	} else {
		t.Error(err)
	}

	// tcp
	if tcpLayer, err := layers.Tcp(); err == nil {
		t.Log("## tcp.dstport:", tcpLayer.DstPort)
	} else {
		t.Error(err)
	}

	// http
	if httpLayer, err := layers.Http(); err == nil {
		t.Log("## http:", httpLayer)
		for _, header := range *httpLayer.ResponseLine {
			t.Log("#### http.ResponseLine >>>", header)
		}
	} else {
		t.Error(err)
	}
}

func TestParseHttps(t *testing.T) {
	pcapPath := "./pcaps/https.pcapng"

	// set TLS config
	tls := TlsConf{
		DesegmentSslRecords:         true,
		DesegmentSslApplicationData: true,
		KeysList: []Key{
			{
				Ip:       "192.168.17.128",
				Port:     443,
				Protocol: "tls",
				KeyFile:  "./pcaps/https.key",
				Password: "",
			},
			{
				Ip:       "2.2.2.2",
				Protocol: "",
				KeyFile:  "./pcaps/https.key",
				Password: "",
			},
			{
				Ip:       "1.1.1.1",
				Port:     0,
				Protocol: "",
				KeyFile:  "./pcaps/testInvalid.key",
				Password: "test1",
			},
		},
	}
	t.Log(tls)

	frameData, err := GetSpecificFrameProtoTreeInJson(pcapPath, 14,
		WithTls(tls), WithDescriptive(true), WithDebug(true))
	if err != nil {
		t.Fatal(err)
	}

	layers := Layers(frameData.WsSource.Layers)

	// ip
	if ipLayer, err := layers.Ip(); err == nil {
		t.Log("## ip.src:", ipLayer.Src)
		t.Log("## ip.dst:", ipLayer.Dst)
	} else {
		t.Error(err)
	}

	// udp
	if udpLayer, err := layers.Udp(); err == nil {
		t.Log("## udp.srcport:", udpLayer.SrcPort)
	} else {
		t.Error(err)
	}

	// tcp
	if tcpLayer, err := layers.Tcp(); err == nil {
		t.Log("## tcp.dstport:", tcpLayer.DstPort)
	} else {
		t.Error(err)
	}

	// http
	if httpLayer, err := layers.Http(); err == nil {
		t.Log("## http:", httpLayer)
		for _, header := range *httpLayer.ResponseLine {
			t.Log("#### http.ResponseLine >>>", header)
		}
	} else {
		t.Error(err)
	}

}

func TestGetSeveralFrameProtoTreeInJson(t *testing.T) {
	nums := []int{11, 5, 0, 1, -1, 13, 288}
	res, err := GetSeveralFrameProtoTreeInJson(inputFilepath, nums,
		WithDescriptive(true), WithDebug(false))
	if err != nil {
		t.Fatal(err)
	}

	// [1 5 11 13]
	for _, frameData := range res {
		layers := Layers(frameData.WsSource.Layers)
		if colLayer, err := layers.WsCol(); err == nil {
			t.Log("# Frame index:", colLayer.Num, "===========================")
			t.Log("## WsIndex:", frameData.WsIndex)
			t.Log("## Offset:", frameData.Offset)
			t.Log("## Hex:", frameData.Hex)
			t.Log("## Ascii:", frameData.Ascii)
		} else {
			t.Error(err)
		}
	}
}

func TestGetAllFrameProtoTreeInJson(t *testing.T) {
	res, err := GetAllFrameProtoTreeInJson(inputFilepath,
		WithDescriptive(true), WithDebug(false))
	if err != nil {
		t.Fatal(err)
	}

	for _, frameData := range res {
		layers := Layers(frameData.WsSource.Layers)
		// _ws.col
		if colLayer, err := layers.WsCol(); err == nil {
			t.Log("# Frame index:", colLayer.Num, "===========================")
			t.Log("## WsIndex:", frameData.WsIndex)
			t.Log("## Offset:", frameData.Offset)
			t.Log("## Hex:", frameData.Hex)
			t.Log("## Ascii:", frameData.Ascii)
		} else {
			t.Error(err)
		}
	}
}

func TestGoroutineGetAllFrameProtoTreeInJson(t *testing.T) {
	var wg sync.WaitGroup
	numGoroutines := 100

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			res, err := GetAllFrameProtoTreeInJson(inputFilepath, WithDescriptive(true), WithDebug(false))
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
			layers := Layers(frameData.WsSource.Layers)
			// _ws.col
			if colLayer, err := layers.WsCol(); err == nil {
				t.Log("# Frame index:", colLayer.Num, "===========================")
				t.Log("## WsIndex:", frameData.WsIndex)
				t.Log("## Offset:", frameData.Offset)
				t.Log("## Hex:", frameData.Hex)
				t.Log("## Ascii:", frameData.Ascii)
			} else {
				t.Error(err)
			}

			// frame
			if frameLayer, err := layers.Frame(); err == nil {
				t.Log("【layer frame】:", frameLayer)
			} else {
				t.Error(err)
			}
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
Set the num parameter of the DissectPktLive function to a specific num like 50
to process packets in a limited loop.
*/
func TestDissectPktLiveSpecificNum(t *testing.T) {
	ifName := "en7"
	filter := ""
	pktNum := 5
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
			layers := Layers(frameData.WsSource.Layers)

			// frame
			if frameLayer, err := layers.Frame(); err == nil {
				t.Log("# Frame index:", frameLayer.Number, "===========================")
				t.Log("【layer frame】:", frameLayer)
			} else {
				t.Error(err)
			}

			// _ws.col
			if colLayer, err := layers.WsCol(); err == nil {
				t.Log("【layer _ws.col】:", colLayer)
			} else {
				t.Error(err)
			}

			// ip
			if ipLayer, err := layers.Ip(); err == nil {
				t.Log("## ip.src:", ipLayer.Src)
				t.Log("## ip.dst:", ipLayer.Dst)
			} else {
				t.Error(err)
			}

			// udp
			if udpLayer, err := layers.Udp(); err == nil {
				t.Log("## udp.srcport:", udpLayer.SrcPort)
			} else {
				t.Error(err)
			}

			// tcp
			if tcpLayer, err := layers.Tcp(); err == nil {
				t.Log("## tcp.dstport:", tcpLayer.DstPort)
			} else {
				t.Error(err)
			}

			// http
			if httpLayer, err := layers.Http(); err == nil {
				t.Log("## http:", httpLayer)
			} else {
				t.Error(err)
			}

		}
	}()

	// set TLS config
	// macos test parse tls1.2
	// curl --tlsv1.2 --tls-max 1.2 --ciphers 'AES128-GCM-SHA256' -k 'https://192.168.xxx.xxx/?id=123'
	tls := TlsConf{
		DesegmentSslRecords:         true,
		DesegmentSslApplicationData: true,
		KeysList: []Key{
			{
				Ip:       "",
				Port:     443,
				Protocol: "",
				KeyFile:  "./pcaps/server.key", // mac test key
				Password: "",
			},
		},
	}

	t.Log(tls)

	// start c client, capture and dissect packet
	err := DissectPktLive(ifName, filter, pktNum, promisc, timeout, WithTls(tls))
	if err != nil {
		t.Fatal(err)
	}
}

func TestBPF(t *testing.T) {
	ifName := "en7"
	filter := "" // tcp port 443
	pktNum := 300
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
			layers := Layers(frameData.WsSource.Layers)

			// frame
			if frameLayer, err := layers.Frame(); err == nil {
				t.Log("# Frame index:", frameLayer.Number, "===========================")
				t.Log("【layer frame】:", frameLayer)
			} else {
				t.Error(err)
			}

			// _ws.col
			if colLayer, err := layers.WsCol(); err == nil {
				t.Log("【layer _ws.col】:", colLayer)
			} else {
				t.Error(err)
			}

			// ip
			if ipLayer, err := layers.Ip(); err == nil {
				t.Log("## ip.src:", ipLayer.Src)
				t.Log("## ip.dst:", ipLayer.Dst)
			} else {
				t.Error(err)
			}

			// udp
			if udpLayer, err := layers.Udp(); err == nil {
				t.Log("## udp.srcport:", udpLayer.SrcPort)
			} else {
				t.Error(err)
			}

			// tcp
			if tcpLayer, err := layers.Tcp(); err == nil {
				t.Log("## tcp.dstport:", tcpLayer.DstPort)
			} else {
				t.Error(err)
			}

			// http
			if httpLayer, err := layers.Http(); err == nil {
				t.Log("## http:", httpLayer)
				for _, header := range *httpLayer.ResponseLine {
					t.Log("#### http.ResponseLine >>>", header)
				}
			} else {
				t.Error(err)
			}

		}
	}()

	// start c client, capture and dissect packet
	err := DissectPktLive(ifName, filter, pktNum, promisc, timeout)
	if err != nil {
		t.Fatal(err)
	}
}
