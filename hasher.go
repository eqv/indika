package main

import (
	"debug/elf"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/go-errors/errors"
	be "github.com/ranmrdrakono/indika/blanket_emulator"
	ds "github.com/ranmrdrakono/indika/data_structures"
	"github.com/ranmrdrakono/indika/disassemble"
	"github.com/ranmrdrakono/indika/arch"
	loader "github.com/ranmrdrakono/indika/loader/elf"
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

func MakeBlanketEmulator(mem map[ds.Range]*ds.MappedRegion) *be.Emulator {
	config := be.Config{
		MaxTraceInstructionCount: 100,
		MaxTraceTime:             0,
		MaxTracePages:            50,
		Arch:                     &arch.ArchX86_64{},
	}
  env := be.NewRandEnv(0)
	em := be.NewEmulator(mem, config, env)
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

func pad_func_name(str string) string {
	name_len := 40
	if len(str) > name_len {
		return str[:name_len]
	}
	pad_len := name_len - len(str)
	pad := make([]byte, pad_len)
	for i := 0; i < pad_len; i++ {
		pad[i] = 0x20
	}
	return str + string(pad)
}

func are_we_interessted_in_this(symb *ds.Symbol) bool{
    if symb.Type != ds.FUNC { return false }
    if len(os.Args) > 2 {
      for _, str := range os.Args {
        if str == symb.Name {
          return true
        }
      }
      return false
    }
    return true
}

func main() {
	file := os.Args[1]

	log.SetLevel(log.ErrorLevel)

	fmt.Printf("%v\n", os.Args)

	if len(os.Args) >= 3 && os.Args[2] == "d" {
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
    if !are_we_interessted_in_this(symb) {
      continue
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
    ev := emulator.Events
    fmt.Printf("hash %v\n", hex.EncodeToString(ev.GetHash(32)))
    log.WithFields(log.Fields{"events": ev.Inspect()}).Debug("Done running Blanket")
    emulator.Close()
    emulator = nil
	}
}
