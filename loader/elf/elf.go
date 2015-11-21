package elf

import (
	"debug/elf"
	"fmt"
	log "github.com/Sirupsen/logrus"
	ds "github.com/ranmrdrakono/indika/data_structures"
	"io"
	"os"
)

func check(e error) {
	if e != nil {
		log.WithFields(log.Fields{"error": e}).Fatal("unexpected error")
		panic(e)
	}
}

func ioReader(file string) io.ReaderAt {
	r, err := os.Open(file)
	check(err)
	return r
}

func elfFlagsToPageFlags(in elf.ProgFlag) ds.PageFlags {
	res := ds.PageFlags(0)
	if in&elf.PF_X != 0 {
		res |= ds.X
	}
	if in&elf.PF_R != 0 {
		res |= ds.R
	}
	if in&elf.PF_W != 0 {
		res |= ds.W
	}
	return res
}

func GetSegments(e *elf.File) map[ds.Range]*ds.MappedRegion {
	res := make(map[ds.Range]*ds.MappedRegion)
	for _, prog_offset := range e.Progs {
		hdr := prog_offset.ProgHeader
		if hdr.Off == 0 && hdr.Filesz == 0 {
			continue
		}
		info := new(ds.MappedRegion)
		info.Range = ds.NewRange(hdr.Vaddr, hdr.Vaddr+hdr.Memsz)
		info.Data = make([]byte, hdr.Filesz, hdr.Filesz)
		info.Flags = elfFlagsToPageFlags(hdr.Flags)
		res[info.Range] = info
		size_read, err := prog_offset.Open().Read(info.Data)
		check(err)
		if uint64(size_read) != hdr.Filesz {
			panic("size missmatch")
		}
	}
	return res
}

const (
	STT_NOTYPE  = 0
	STT_OBJECT  = 1
	STT_FUNC    = 2
	STT_SECTION = 3
	STT_FILE    = 4
	STT_COMMON  = 5
	STT_TLS     = 6
)

func elfSymbolTypeToSymbolType(elfsymbol uint) ds.SymbolType {
	switch elfsymbol & 0xf {
	case STT_OBJECT:
		return ds.DATA
	case STT_COMMON:
		return ds.DATA
	case STT_FUNC:
		return ds.FUNC
	case STT_FILE:
		return ds.FILE
	case STT_TLS:
		return ds.THREADLOCAL
	case STT_SECTION:
		return ds.SECTION
	}
	log.WithFields(log.Fields{"elfsymbol": elfsymbol & 0xf}).Info("Failed to Interpret Symbol")
	return ds.UNKNOWN
}

func GetSymbols(e *elf.File) map[ds.Range]*ds.Symbol {
	res := make(map[ds.Range]*ds.Symbol)
	symbols, err := e.Symbols()
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Info("Failed to Parse Symbols")
		return res
	}
	for _, sym := range symbols {
		sym_type := elfSymbolTypeToSymbolType(uint(sym.Info))
		symbol := ds.NewSymbol(sym.Name, sym_type)
		fmt.Printf("symbol %v\n", symbol)
		res[ds.NewRange(sym.Value, sym.Value+sym.Size)] = symbol
	}
	return res
}

func Run(file string) {
	f := ioReader(file)
	_elf, err := elf.NewFile(f)
	check(err)
	maps := GetSegments(_elf)
	_ = GetSymbols(_elf)
	fmt.Printf("%v\n", maps)
}
