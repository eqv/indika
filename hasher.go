package main

import (
	"debug/elf"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/go-errors/errors"
	be "github.com/ranmrdrakono/indika/blanket_emulator"
	ds "github.com/ranmrdrakono/indika/data_structures"
	"github.com/ranmrdrakono/indika/disassemble"
	loader "github.com/ranmrdrakono/indika/loader/elf"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
	"io"
	"os"
	//	"reflect"
  "encoding/hex"
)

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

func MakeBlanketEmulator(mem map[ds.Range]*ds.MappedRegion) *be.Emulator {
	ev := be.NewEventsToMinHash()
	config := be.Config{
		MaxTraceInstructionCount: 100,
		MaxTraceTime:             0,
		MaxTracePages:            50,
		Arch:                     uc.ARCH_X86,
		Mode:                     uc.MODE_64,
		EventHandler:             ev,
	}
	em := be.NewEmulator(mem, config)
	return em
}

func ioReader(file string) io.ReaderAt {
	r, err := os.Open(file)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Fatal("Error creating File Reader")
	}
	return r
}

func wrap(err error) *errors.Error {
	if err != nil {
		return errors.Wrap(err, 1)
	}
	return nil
}

func check(err *errors.Error) {
	if err != nil && err.Err != nil {
		log.WithFields(log.Fields{"error": err, "stack": err.ErrorStack()}).Fatal("Error creating Elf Parser")
	}
}

func pad_func_name(str string) string{
  name_len := 40
  if len(str) > name_len {return str[:name_len]}
  pad_len := name_len-len(str)
  pad := make([]byte, pad_len)
  for i:= 0; i < pad_len; i++ {pad[i]=0x20}
  return str+string(pad)
}

func main(){
	file := os.Args[1]

	log.SetLevel(log.ErrorLevel)

  fmt.Printf("%v\n",os.Args)

  if len(os.Args) >=3 && os.Args[2] == "d"{
	  log.SetLevel(log.DebugLevel)
  }

	f := ioReader(file)
	_elf, err := elf.NewFile(f)
	check(wrap(err))
	maps := loader.GetSegments(_elf)

	symbols := loader.GetSymbols(_elf)
	fmt.Println("done loading")
  fmt.Printf("maps %v\n", maps)

	for rng, symb := range symbols {
		if symb.Type == ds.FUNC {
      if len(os.Args) > 2 {
        found := false
        for _,str := range os.Args {
          if str == symb.Name {
            found = true
          }
        }
        if !found {continue;}
      }
			bbs := extract_bbs(maps, rng)
			if len(bbs) == 0 {
				continue
			}
      fmt.Printf("%v : ", pad_func_name(symb.Name))
      emulator := MakeBlanketEmulator(maps)
			err := emulator.FullBlanket(bbs)
			if err != nil {
				log.WithFields(log.Fields{"error": err}).Error("Error running Blanket")
        continue
			}
			ev := emulator.Config.EventHandler.(*be.EventsToMinHash)
			fmt.Printf("hash %v\n", hex.EncodeToString(ev.GetHash(32)))
			log.WithFields(log.Fields{"events": ev.Inspect()}).Debug("Done running Blanket")
      emulator.Close()
      emulator = nil
		}
	}
}
