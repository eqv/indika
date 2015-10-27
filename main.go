package main

import (
	"encoding/hex"
	"fmt"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
  "github.com/ranmrdrakono/function_hasher/trace"
	"strings"
)

var asm = strings.Join([]string{
	"48c7c003000000", // mov rax, 3
	//"0f05",           // syscall
	"bf03400000",       // mov rdi, 0x4000
  "ba04000000",       // mov rdx, 4
	"8b17",             // mov rdx, [rdi]
  "48ffc7",           // inc rdi
	"8b17",             // mov rdx, [rdi]
}, "")

func run(t *trace.Trace) error {
	code, err := hex.DecodeString(asm)
	if err != nil {
		return err
	}
	// set up unicorn instance and add hooks
	mu, err := uc.NewUnicorn(uc.ARCH_X86, uc.MODE_64)

	if err != nil {
		return err
	}

	t.AddHooks(mu)
	// map and write code to memory
	if err := mu.MemMap(0x1000, 0x1000); err != nil {
		return err
	}
	if err := mu.MemWrite(0x1000, code); err != nil {
		return err
	}

	// set example register
	if err := mu.RegWrite(uc.X86_REG_RDX, trace.GetReg(3)); err != nil {
		return err
	}

	rdx, err := mu.RegRead(uc.X86_REG_RDX)
	if err != nil {
		return err
	}

	fmt.Printf("RDX old is : %d\n", rdx)

	// start emulation
	if err := mu.Start( 0x1000, 0x1000+uint64(len(code)) ); err != nil {
		return err
	}

	// read back example register
	rdx, err = mu.RegRead(uc.X86_REG_RDX)
	if err != nil {
		return err
	}
	fmt.Printf("RDX is now: %d\n", rdx)
	return nil
}

func main() {
	code,_ := hex.DecodeString(asm)
  
  blocks_to_visit := make(map[trace.BlockRange]bool);
  for i := uint64(0); i < uint64(len(code)); i++ {
    blocks_to_visit[trace.NewBlockRange(i+0x1000,i+0x1000+1)] = true;
  }
  t := trace.NewTrace(50, &blocks_to_visit);
	if err := run(t); err != nil {
		fmt.Println(err)
	}
  fmt.Println("%v", t.GetHash(80))
}
