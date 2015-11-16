package indika

import (
  "testing"
  "debug/elf"
  "os"
  "io"
  "fmt"
  "github.com/go-errors/errors"
  loader "github.com/ranmrdrakono/indika/loader/elf"
  "github.com/ranmrdrakono/indika/disassemble"
  be "github.com/ranmrdrakono/indika/blanket_emulator"
  ds "github.com/ranmrdrakono/indika/data_structures"
	log "github.com/Sirupsen/logrus"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
)


func find_mapping_for(maps map[ds.Range]*ds.MappedRegion, needle ds.Range)*ds.MappedRegion{
  for rng, mapping := range maps {
    if rng.IntersectsRange(needle) {
      return mapping
    }
  }
  return nil
}

func extract_bbs(maps map[ds.Range]*ds.MappedRegion, rng ds.Range) map[ds.Range]bool{
  maped := find_mapping_for(maps,rng)
  if(maped == nil){return nil}
  return disassemble.GetBasicBlocks(maped.Range.From, maped.Data, rng)
}

func mapKeysRangeToStarts(mem map[ds.Range]*ds.MappedRegion) map[uint64][]byte{
  res := make(map[uint64][]byte)
  for key,val := range mem {
    res[key.From]=(*val).Data
  }
  return res
}

func MakeBlanketEmulator(mem map[ds.Range]*ds.MappedRegion) *be.Emulator {
	ev := be.NewEventsToMinHash()
	config := be.Config{
		MaxTraceInstructionCount: 1000,
		MaxTraceTime:             0,
		MaxTracePages:            100,
		Arch:                     uc.ARCH_X86,
		Mode:                     uc.MODE_64,
		EventHandler:             ev,
	}
  mem_starts := mapKeysRangeToStarts(mem)
	em, err := be.NewEmulator(mem_starts, config)
  if(err != nil) { log.WithFields(log.Fields{"error": err}).Fatal("Error creating Emulator")}
  return em
}

func ioReader(file string) io.ReaderAt {
    r, err := os.Open(file)
    if(err != nil) { log.WithFields(log.Fields{"error": err}).Fatal("Error creating File Reader")}
    return r
}

func wrap(err error) *errors.Error{
  if err != nil {
    return errors.Wrap(err,1)
  }
  return nil
}

func check(err *errors.Error){
  if(err!=nil && err.Err != nil) { log.WithFields(log.Fields{"error": err, "stack": err.ErrorStack()}).Fatal("Error creating Elf Parser")}
}

func TestRun(t *testing.T) {
  file := "samples/binutils/bin_O0/gdb"
	f := ioReader(file)
	_elf, err := elf.NewFile(f)
  check( wrap(err) )
	maps := loader.GetSegments(_elf)
  symbols := loader.GetSymbols(_elf)
  fmt.Println("done loading")
  emulator := MakeBlanketEmulator(maps)

  for rng, symb := range symbols {
    if symb.Type == ds.FUNC {
      bbs := extract_bbs(maps, rng)
      err := emulator.FullBlanket(bbs)
      if(err != nil) { log.WithFields(log.Fields{"error": err}).Fatal("Error running Blanket")}
      ev := emulator.Config.EventHandler.(*be.EventsToMinHash)
	    fmt.Println("hash %v", ev.GetHash(80))
    }
  }
}
