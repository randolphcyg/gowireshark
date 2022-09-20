package tests

import (
	"fmt"
	"testing"

	"github.com/randolphcyg/gowireshark"
)

const inputFilepath = "../pcaps/s7comm_clean.pcap"

func TestEpanVersion(t *testing.T) {
	fmt.Println(gowireshark.EpanVersion())
}

func TestEpanPluginsSupported(t *testing.T) {
	fmt.Println(gowireshark.EpanPluginsSupported())
}

func TestDissectAllFrame(t *testing.T) {
	err := gowireshark.DissectAllFrame(inputFilepath)
	if err != nil {
		fmt.Println(err)
	}

}

func TestDissectFirstFrame(t *testing.T) {
	err := gowireshark.DissectFirstFrame(inputFilepath)
	if err != nil {
		fmt.Println(err)
	}

}

func TestDissectFirstSeveralFrame(t *testing.T) {
	err := gowireshark.DissectFirstSeveralFrame(inputFilepath, 2000)
	if err != nil {
		fmt.Println(err)
	}

}

func TestDissectSpecificFrame(t *testing.T) {
	err := gowireshark.DissectSpecificFrame(inputFilepath, 5000)
	if err != nil {
		fmt.Println(err)
	}
}

/*
RESULT: none
*/
func TestDissectSpecificFrameOutOfBounds(t *testing.T) {
	err := gowireshark.DissectSpecificFrame(inputFilepath, 5448)
	if err != nil {
		fmt.Println(err)
	}
}

func TestDissectSpecificFrameByGo(t *testing.T) {
	err := gowireshark.DissectSpecificFrame(inputFilepath, 5000)
	if err != nil {
		fmt.Println(err)
	}
}

/*
RESULT: 5448: frame index is out of bounds
*/
func TestDissectSpecificFrameByGoOutOfBounds(t *testing.T) {
	err := gowireshark.DissectSpecificFrame(inputFilepath, 5448)
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
func TestProtoTreeToJsonAllFrame(t *testing.T) {
	resBytes, err := gowireshark.ProtoTreeToJsonAllFrame(inputFilepath)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Printf("%s\n", resBytes)
}

func TestProtoTreeToJsonSpecificFrame(t *testing.T) {
	resBytes, err := gowireshark.ProtoTreeToJsonSpecificFrame(inputFilepath, 2)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Printf("%s\n", resBytes)
}

func TestGetSpecificFrameHexData(t *testing.T) {
	err := gowireshark.GetSpecificFrameHexData(inputFilepath, 2)
	if err != nil {
		fmt.Println(err)
	}
}
