package blanket_emulator

import (
	"fmt"
	log "github.com/Sirupsen/logrus"
	ds "github.com/ranmrdrakono/indika/data_structures"
	"github.com/ranmrdrakono/indika/disassemble"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
	"reflect"
	"testing"
)

func init() {
	log.SetLevel(log.DebugLevel)
	//log.SetLevel(log.ErrorLevel)
}

func find_mapping_for(maps map[ds.Range]*ds.MappedRegion, needle ds.Range) *ds.MappedRegion {
	for rng, mapping := range maps {
		if rng.IntersectsRange(needle) {
			return mapping
		}
	}
	return nil
}
func filter_empty_bbs(bbs map[ds.Range]bool) map[ds.Range]bool {
	res := make(map[ds.Range]bool)
	for rng, _ := range bbs {
		if !rng.IsEmpty() {
			res[rng] = true
		}
	}
	return res
}

func extract_bbs(maps map[ds.Range]*ds.MappedRegion, rng ds.Range) map[ds.Range]bool {
	maped := find_mapping_for(maps, rng)
	if maped == nil {
		return nil
	}
	blocks := disassemble.GetBasicBlocks(maped.Range.From, maped.Data, rng)
	fmt.Println("BBS without filter:", blocks, rng)
	return filter_empty_bbs(blocks)
}

func MakeBlanketEmulator(mem map[ds.Range]*ds.MappedRegion) *Emulator {
	ev := NewEventsToMinHash()
	config := Config{
		MaxTraceInstructionCount: 100,
		MaxTraceTime:             0,
		MaxTracePages:            100,
		Arch:                     uc.ARCH_X86,
		Mode:                     uc.MODE_64,
		EventHandler:             ev,
	}
	em := NewEmulator(mem, config)
	return em
}

func TestOneInstruction(t *testing.T) {
	maps := make(map[ds.Range]*ds.MappedRegion)
	content := "\x48\x8b\x00"
	base := uint64(0x40000)
	rng := ds.NewRange(base, base+uint64(len(content)))
	maps[rng] = ds.NewMappedRegion([]byte(content), ds.R|ds.X, rng)
	emulator := MakeBlanketEmulator(maps)

	bbs := extract_bbs(maps, rng)
	expected_bbs := map[ds.Range]bool{ds.NewRange(base, base+uint64(len(content))): true}
	if !reflect.DeepEqual(bbs, expected_bbs) {
		fmt.Printf("disassembly failure")
	}
	fmt.Println("BBS: %v %v", len(bbs), bbs)
	err := emulator.FullBlanket(bbs)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Fatal("Error running Blanket")
	}
	ev := emulator.Config.EventHandler.(*EventsToMinHash)
	fmt.Println("events for single instruction %v", ev.Inspect())

	//expected_events := map[ds.Range]bool{ds.NewRange(4195607, 4195626): true, ds.NewRange(4195631, 4195644): true, ds.NewRange(4195646, 4195664): true, ds.NewRange(4195669, 4195678): true, ds.NewRange(4195680, 4195681): true}
	//ev := emulator.Config.EventHandler.(*EventsToMinHash)
	//if !reflect.DeepEqual(bbs, expected_bbs) {
	//	fmt.Printf("disassembly failure")
	//}
}

func TestRun(t *testing.T) {
	maps := make(map[ds.Range]*ds.MappedRegion)
	content := "\x48\x8b\x00\x48\x8b\x00\x48\x8b\x00\x48\x89\x03\xcd\x50"
	base := uint64(0x40000)
	rng := ds.NewRange(base, base+uint64(len(content)))
	maps[rng] = ds.NewMappedRegion([]byte(content), ds.R|ds.X, rng)
	emulator := MakeBlanketEmulator(maps)

	bbs := extract_bbs(maps, rng)
	//expected_bbs := map[ds.Range]bool{ds.NewRange(4195607, 4195626): true, ds.NewRange(4195631, 4195644): true, ds.NewRange(4195646, 4195664): true, ds.NewRange(4195669, 4195678): true, ds.NewRange(4195680, 4195681): true}
	//if !reflect.DeepEqual(bbs, expected_bbs) {
	//	fmt.Printf("disassembly failure")
	//}
	err := emulator.FullBlanket(bbs)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Fatal("Error running Blanket")
	}
	ev := emulator.Config.EventHandler.(*EventsToMinHash)
	fmt.Println("events for single BB %v", ev.Inspect())
}
