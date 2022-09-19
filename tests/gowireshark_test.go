package tests

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/randolphcyg/gowireshark"
)

func TestEpanVersion(t *testing.T) {
	fmt.Println(gowireshark.EpanVersion())
}

func TestEpanPluginsSupported(t *testing.T) {
	fmt.Println(gowireshark.EpanPluginsSupported())
}

func TestDissectAllFrame(t *testing.T) {
	filepath := "../pcaps/s7comm_clean.pcap"
	err := gowireshark.DissectAllFrame(filepath)
	if err != nil {
		fmt.Println(err)
	}

}

func TestDissectFirstFrame(t *testing.T) {
	filepath := "../pcaps/s7comm_clean.pcap"
	err := gowireshark.DissectFirstFrame(filepath)
	if err != nil {
		fmt.Println(err)
	}

}

func TestDissectFirstSeveralFrame(t *testing.T) {
	filepath := "../pcaps/s7comm_clean.pcap"
	err := gowireshark.DissectFirstSeveralFrame(filepath, 2000)
	if err != nil {
		fmt.Println(err)
	}

}

func TestDissectSpecificFrame(t *testing.T) {
	filepath := "../pcaps/s7comm_clean.pcap"
	err := gowireshark.DissectSpecificFrame(filepath, 5000)
	if err != nil {
		fmt.Println(err)
	}
}

/*
RESULT: none
*/
func TestDissectSpecificFrameOutOfBounds(t *testing.T) {
	filepath := "../pcaps/s7comm_clean.pcap"
	err := gowireshark.DissectSpecificFrame(filepath, 5448)
	if err != nil {
		fmt.Println(err)
	}
}

func TestDissectSpecificFrameByGo(t *testing.T) {
	filepath := "../pcaps/s7comm_clean.pcap"
	err := gowireshark.DissectSpecificFrame(filepath, 5000)
	if err != nil {
		fmt.Println(err)
	}
}

/*
RESULT: 5448: frame index is out of bounds
*/
func TestDissectSpecificFrameByGoOutOfBounds(t *testing.T) {
	filepath := "../pcaps/s7comm_clean.pcap"
	err := gowireshark.DissectSpecificFrame(filepath, 5448)
	if err != nil {
		fmt.Println(err)
	}
}

/*
RESULT:
map[1:{"_index":"packets-2017-06-09",
"_type":"doc",
"_score":{},
"ascii":{},
"hex":{},
"offset":{},
"_source":{"layers":{"frame":{}}}}}}]
*/
func TestProtoTreeToJsonSpecificFrame(t *testing.T) {
	all := make(map[string]string)
	inputFilepath := "../pcaps/s7comm_clean.pcap"

	// init cap file only once
	err := gowireshark.InitCapFile(inputFilepath)
	if err != nil {
		fmt.Println(err)
		return
	}

	counter := 1

	for {
		frameData, err := gowireshark.ProtoTreeToJsonSpecificFrame(counter)
		if err != nil {
			fmt.Println(err)
			break
		}

		all[strconv.Itoa(counter)] = frameData
		counter++

		if frameData == "" {
			fmt.Println("result is blank")
			break
		}

		if counter == 5 {
			break
		}

	}

	fmt.Println(all)
}
