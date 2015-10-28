package main

import (
	"encoding/hex"
	"fmt"
	"github.com/ranmrdrakono/indika/blanket_emulator"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
	"strings"
)

var asm = strings.Join([]string{
	"48c7c003000000", // mov rax, 3
	//"0f05",           // syscall
	"bf03400000", // mov rdi, 0x4000
	"ba04000000", // mov rdx, 4
	"8b17",       // mov rdx, [rdi]
	"48ffc7",     // inc rdi
	"8b17",       // mov rdx, [rdi]
	"48ffc7",     // inc rdi
	"8b17",       // mov rdx, [rdi]
}, "")

type fakeDisassembler struct{}

func (s *fakeDisassembler) GetBlocks(addr uint64, codepages map[uint64]([]byte)) map[blanket_emulator.BlockRange]bool {
	res := make(map[blanket_emulator.BlockRange]bool)
	for paddr, val := range codepages {
		if paddr <= addr && paddr+uint64(len(val)) >= addr {
			for byteaddr := addr; byteaddr < addr+uint64(len(val)); byteaddr += 1 {
				res[blanket_emulator.BlockRange{From: byteaddr, To: byteaddr + 1}] = true
			}
		}
	}
	return res
}

func run() error {
	code, err := hex.DecodeString(asm)
	if err != nil {
		return err
	}

	config := blanket_emulator.Config{
		MaxTraceInstructionCount: 1000,
		MaxTraceTime:             0,
		MaxTracePages:            100,
		Arch:                     uc.ARCH_X86,
		Mode:                     uc.MODE_64,
		Disassembler:             &fakeDisassembler{},
	}

	mem := make(map[uint64]([]byte))
	mem[0x1000] = code
	em, err := blanket_emulator.NewEmulator(mem, config)

	if err != nil {
		return err
	}

	err = em.Run(0x1000)

	if err != nil {
		return err
	}

	fmt.Println("%v", em.GetHash(80))

	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Println("%v", err)
	}
}
