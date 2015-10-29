package blanket_emulator

import (
	"encoding/hex"
	"fmt"
  "testing"
//	"github.com/ranmrdrakono/indika/blanket_emulator"
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

func GetBlocks(addr uint64, codepages map[uint64]([]byte)) map[BlockRange]bool {
	res := make(map[BlockRange]bool)
	for paddr, val := range codepages {
		if paddr <= addr && paddr+uint64(len(val)) >= addr {
			for byteaddr := addr; byteaddr < addr+uint64(len(val)); byteaddr += 1 {
				res[BlockRange{From: byteaddr, To: byteaddr + 1}] = true
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

	ev := NewEventsToMinHash()
	config := Config{
		MaxTraceInstructionCount: 1000,
		MaxTraceTime:             0,
		MaxTracePages:            100,
		Arch:                     uc.ARCH_X86,
		Mode:                     uc.MODE_64,
		EventHandler:             ev,
	}

	mem := make(map[uint64]([]byte))
	mem[0x1000] = code
	em, err := NewEmulator(mem, config)

	if err != nil {
		return err
	}

	err = em.FullBlanket(GetBlocks(0x1000, mem))

	if err != nil {
		return err
	}

	fmt.Println("%v", ev.GetHash(80))

	return nil
}

func TestRun(t *testing.T) {
	if err := run(); err != nil {
		fmt.Println("%v", err)
	}
}
