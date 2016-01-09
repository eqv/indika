package blanket_emulator

import (
	"fmt"
	log "github.com/Sirupsen/logrus"
	ds "github.com/ranmrdrakono/indika/data_structures"
	"github.com/ranmrdrakono/indika/disassemble"
	"github.com/ranmrdrakono/indika/arch"
  "encoding/binary"
	"reflect"
	"testing"
)

func init() {
	//log.SetLevel(log.DebugLevel)
	log.SetLevel(log.ErrorLevel)
}

func find_mapping_for(maps map[ds.Range]*ds.MappedRegion, needle ds.Range) *ds.MappedRegion {
	for rng, mapping := range maps {
		if rng.IntersectsRange(needle) {
			return mapping
		}
	}
	return nil
}

func filter_empty_bbs(bbs map[uint64]ds.BB) map[uint64]ds.BB {
	res := make(map[uint64]ds.BB)
	for addr, bb := range bbs {
		if !bb.Rng.IsEmpty() {
			res[addr] = bb
		}
	}
	return res
}

func extract_bbs(maps map[ds.Range]*ds.MappedRegion, rng ds.Range) map[uint64]ds.BB {
	maped := find_mapping_for(maps, rng)
	if maped == nil {
		return nil
	}
	blocks := disassemble.GetBBs(maped.Range.From, maped.Data, rng)
	return filter_empty_bbs(blocks)
}

func MakeBlanketEmulator(mem map[ds.Range]*ds.MappedRegion, env Environment) *Emulator {
	config := Config{
		MaxTraceInstructionCount: 100,
		MaxTraceTime:             0,
		MaxTracePages:            100,
		Arch:                     &arch.ArchX86_64{},
	}
	em := NewEmulator(mem, config, env)
	return em
}

func TestOneInstruction(t *testing.T) {
	maps := make(map[ds.Range]*ds.MappedRegion)
  content := "H\x8B\x00\xC3"
	base := uint64(0x40000)
	rng := ds.NewRange(base, base+uint64(len(content)))
	maps[rng] = ds.NewMappedRegion([]byte(content), ds.R|ds.X, rng)
  env := NewRandEnv(0)
	emulator := MakeBlanketEmulator(maps, env)

	bbs := extract_bbs(maps, rng)
  expected_bbs := map[uint64]ds.BB{base: *ds.NewBB(base, base+uint64(len(content)), []uint64{}) }
	if !reflect.DeepEqual(bbs, expected_bbs) {
    fmt.Printf("disassembly failure, Should be:\n%#v\nIs       :\n%#v\n", expected_bbs, bbs)
    t.Fail()
	}
	err := emulator.FullBlanket(bbs)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Error running Blanket")
    t.Fail()
	}
  ev := emulator.Events
  rax := env.GetReg(1)
  mem := binary.LittleEndian.Uint64( env.GetMem(rax,8) )
  expected_events:= EventSet{ReadEvent(rax):true, ReturnEvent(mem):true}

	if !reflect.DeepEqual(ev, &expected_events) {
		fmt.Printf("disassembly failure\n%#v\n%#v", *ev, expected_events)
    t.Fail()
	}
}

func TestRun(t *testing.T) {
	maps := make(map[ds.Range]*ds.MappedRegion)
  content := "H\x8B\x00H\x8B\x00H\x8B\x00H\x89\x03\x0F\x05\xC3"
	base := uint64(0x40000)
	rng := ds.NewRange(base, base+uint64(len(content)))
	maps[rng] = ds.NewMappedRegion([]byte(content), ds.R|ds.X, rng)
  env := NewRandEnv(0)
	emulator := MakeBlanketEmulator(maps, env)

	bbs := extract_bbs(maps, rng)
	//expected_bbs := map[ds.Range]bool{ds.NewRange(4195607, 4195626): true, ds.NewRange(4195631, 4195644): true, ds.NewRange(4195646, 4195664): true, ds.NewRange(4195669, 4195678): true, ds.NewRange(4195680, 4195681): true}
	//if !reflect.DeepEqual(bbs, expected_bbs) {
	//	fmt.Printf("disassembly failure")
	//}
	err := emulator.FullBlanket(bbs)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Fatal("Error running Blanket")
	}

  rax := env.GetReg(1)
  mem1 := binary.LittleEndian.Uint64( env.GetMem(rax,8) )
  mem2 := binary.LittleEndian.Uint64( env.GetMem(mem1,8) )
  mem3 := binary.LittleEndian.Uint64( env.GetMem(mem2,8) )
  rbx := env.GetReg(2)
  expected_events:= EventSet{ReadEvent(rax):true, ReadEvent(mem1):true, ReadEvent(mem2):true, WriteEvent{Addr: rbx,
  Value: mem3}:true, ReturnEvent(mem3):true}
  ev := emulator.Events
	if !reflect.DeepEqual(ev, &expected_events) {
		fmt.Printf("disassembly failure\n%#v\n%#v", *ev, expected_events)
    t.Fail()
	}
}
