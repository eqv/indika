package blanket_emulator

import (
	log "github.com/Sirupsen/logrus"
	ds "github.com/ranmrdrakono/indika/data_structures"
	"github.com/ranmrdrakono/indika/disassemble"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
	"reflect"
	"testing"
  "encoding/binary"
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
	return filter_empty_bbs(blocks)
}

func mapKeysRangeToStarts(mem map[ds.Range]*ds.MappedRegion) map[uint64][]byte {
	res := make(map[uint64][]byte)
	for key, val := range mem {
		res[key.From] = (*val).Data
	}
	return res
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
	mem_starts := mapKeysRangeToStarts(mem)
	em, err := NewEmulator(mem_starts, config)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Fatal("Error creating Emulator")
	}
	return em
}

func TestOneInstruction(t *testing.T){
  maps := make(map[ds.Range]*ds.MappedRegion)
  content := "\x48\x8b\x00"
  base := uint64(0x40000)
  rng := ds.NewRange(base,base+uint64(len(content)))
  maps[rng] = ds.NewMappedRegion([]byte(content), ds.R|ds.X, rng)
	emulator := MakeBlanketEmulator(maps)

  bbs := extract_bbs(maps, rng)
  expected_bbs := map[ds.Range]bool{ds.NewRange(base, base+uint64(len(content))): true}
  if !reflect.DeepEqual(bbs, expected_bbs) {
    t.Error("Disassembly failure, expected:", expected_bbs, " got:",bbs )
  }
  err := emulator.FullBlanket(bbs)
  if err != nil {
    t.Error("Runnin Blanket", err)
  }

  rax := GetReg(1)

  expected_events_set :=  map[Event]bool{ 
    ReadEvent(rax): true, 
  }

  expected_events := EventsToMinHash{Events: expected_events_set}

  ev := emulator.Config.EventHandler.(*EventsToMinHash)
  if !reflect.DeepEqual(ev, &expected_events) {
    t.Error("Wrong Events, expected:", expected_events.Inspect(), " got: ", ev.Inspect())
  }
}


func TestRun(t *testing.T) {
  maps := make(map[ds.Range]*ds.MappedRegion)
  content := "\x48\x8b\x00\x48\x8b\x00\x48\x8b\x00\x48\x89\x03\x0f\x05\x90"
  base := uint64(0x40000)
  rng := ds.NewRange(base,base+uint64(len(content)))
  maps[rng] = ds.NewMappedRegion([]byte(content), ds.R|ds.X, rng)
	emulator := MakeBlanketEmulator(maps)

  bbs := extract_bbs(maps, rng)
  expected_bbs := map[ds.Range]bool{ds.NewRange(base, base+uint64(len(content))): true}
  if !reflect.DeepEqual(bbs, expected_bbs) {
    t.Error("Disassembly failure, expected:", expected_bbs, " got:",bbs )
  }
  err := emulator.FullBlanket(bbs)
  if err != nil {
    t.Error("Runnin Blanket", err)
  }
  ev := emulator.Config.EventHandler.(*EventsToMinHash)

  rax := GetReg(1)
  mem1 := binary.LittleEndian.Uint64(GetMem(rax,8));
  mem2 := binary.LittleEndian.Uint64(GetMem(mem1,8));
  mem3 := binary.LittleEndian.Uint64(GetMem(mem2,8));

  expected_events_set :=  map[Event]bool{ 
    ReadEvent(rax): true, 
    ReadEvent(mem1): true, 
    ReadEvent(mem2): true,
    WriteEvent{Addr: GetReg(2), Value: mem3}: true, 
    SyscallEvent(mem3): true }

  expected_events := EventsToMinHash{Events: expected_events_set}
  if !reflect.DeepEqual(ev, &expected_events) {
    t.Error("Wrong Events, expected:", expected_events.Inspect(), " got: ", ev.Inspect())
  }
}
