package disassemble

import (
	"testing"
  "fmt"
	ds "github.com/ranmrdrakono/indika/data_structures"
	"reflect"
)

var 
code = "\x55\x48\x89\xe5\x89\x7d\xec\x89\x75\xe8\x8b" +
	"\x45\xe8\x01\x45\xec\xd1\x65\xe8\x8b\x55\xec" +
	"\x8b\x45\xe8\x01\xd0\x3d\x38\x05\x00\x00\x75" +
	"\x14\xc7\x45\xfc\x00\x00\x00\x00\xc7\x45\xec" +
	"\x00\x00\x00\x00\x83\x45\xe8\x02\xeb\x20\xc7" +
	"\x45\xfc\x06\x00\x00\x00\x8b\x45\xe8\x01\x45" +
	"\xec\x8b\x55\xec\x8b\x45\xfc\x01\xd0\x85\xc0" +
	"\x75\x07\xb8\x00\x00\x00\x00\xeb\x05\xb8\x01" +
	"\x00\x00\x00\x5d\xc3"

func TestRun(t *testing.T) {
    expected_result := make(map[uint64]ds.BB)
    expected_result[0x1000] = *ds.NewBB(0x1000,0x1022, []uint64{0x1036,0x1022})
    expected_result[0x1022] = *ds.NewBB(0x1022,0x1036, []uint64{0x1056,0x1036})
    expected_result[0x1036] = *ds.NewBB(0x1036,0x104f, []uint64{0x1056,0x104f})
    expected_result[0x104f] = *ds.NewBB(0x104f,0x1056, []uint64{0x105b,0x1056})
    expected_result[0x1056] = *ds.NewBB(0x1056,0x105d, []uint64{})

    blocks := GetBBs(0x1000, []byte(code), ds.NewRange(0x1000,0x1000+uint64(len(code))))
    if !reflect.DeepEqual(blocks, expected_result) {
      fmt.Printf("Is: %#v\n", blocks)
      fmt.Printf("Sh: %#v\n", expected_result)
      t.Fail()
    }
}

//O0 strings str_reverse  [[4195646,4195664],[4195669,4195678],[4195680,4195681],[4195607,4195626],[4195631,4195644]].map{|x| x.map{|y| y.to_s 16 }}
