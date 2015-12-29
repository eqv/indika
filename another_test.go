package indika

import (
	"fmt"
	log "github.com/Sirupsen/logrus"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
//	be "github.com/ranmrdrakono/indika/blanket_emulator"
	"github.com/go-errors/errors"
	"testing"
)

func addHooks(mu uc.Unicorn) error {

  _,err := mu.HookAdd(uc.HOOK_BLOCK, func(mu uc.Unicorn, addr uint64, size uint32) {
		fmt.Printf("Block: 0x%x, 0x%x\n", addr, size)
	})
  if err != nil {
    return err
  }

	_,err = mu.HookAdd(uc.HOOK_CODE, func(mu uc.Unicorn, addr uint64, size uint32) {
		fmt.Printf("Code: 0x%x, 0x%x\n", addr, size)
	})
  if err != nil {
    return err
  }

	_,err = mu.HookAdd(uc.HOOK_MEM_READ|uc.HOOK_MEM_WRITE, func(mu uc.Unicorn, access int, addr uint64, size int, value int64) {
		if access == uc.MEM_WRITE {
			fmt.Printf("Mem write")
		} else {
			fmt.Printf("Mem read")
		}
		fmt.Printf(": @0x%x, 0x%x = 0x%x\n", addr, size, value)
	})
  if err != nil {
    return err
  }

	invalid := uc.HOOK_MEM_READ_INVALID | uc.HOOK_MEM_WRITE_INVALID | uc.HOOK_MEM_FETCH_INVALID
	_,err = mu.HookAdd(invalid, func(mu uc.Unicorn, access int, addr uint64, size int, value int64) bool {
		switch access {
		case uc.MEM_WRITE_UNMAPPED, uc.MEM_WRITE_PROT:
			fmt.Printf("invalid write")
		case uc.MEM_READ_UNMAPPED, uc.MEM_READ_PROT:
			fmt.Printf("invalid read")
		case uc.MEM_FETCH_UNMAPPED, uc.MEM_FETCH_PROT:
			fmt.Printf("invalid fetch")
      return false
		default:
			fmt.Printf("unknown memory error %d\n", access)
      return false
		}
		fmt.Printf(": @0x%x, 0x%x = 0x%x\n", addr, size, value)
    //err := mu.MemMap(addr - (addr % 4096), 0x1000)
    //if err != nil {panic(err)}
		return false
	})
  if err != nil {
    return err
  }

  _,err = mu.HookAdd(uc.HOOK_INSN, func(mu uc.Unicorn) {
		rax, _ := mu.RegRead(uc.X86_REG_RAX)
		fmt.Printf("Syscall: %d\n", rax)
	}, uc.X86_INS_SYSCALL)
    return err
}



func run() error {
  code := []byte("\x48\x8b\x00\x48\x8b\x00\x48\x8b\x00\x48\x89\x03\x0f\x05\x90")

	// set up unicorn instance and add hooks
	mu, err := uc.NewUnicorn(uc.ARCH_X86, uc.MODE_64)
	if err != nil {
		return err
	}

  if err := addHooks(mu); err != nil {
		return err
  }

	// map and write code to memory
	//if err := mu.MemMapProt(0x1000, 0x1000, uc.PROT_READ|uc.PROT_WRITE|uc.PROT_EXEC); err != nil {
	if err := mu.MemMapProt(0x1000, 0x1000, uc.PROT_READ|uc.PROT_WRITE); err != nil {
		return err
	}
	if err := mu.MemWrite(0x1000, code); err != nil {
		return err
	}
	//// map scratch space
	//if err := mu.MemMap(0x4000, 0x1000); err != nil {
	//	return err
	//}
	// set example register
	if err := mu.RegWrite(uc.X86_REG_RAX, 0x1000); err != nil {
		return err
	}

	// start emulation
  if err := mu.StartWithOptions(0x1000, 0x1000+uint64(len(code)), &uc.UcOptions{Timeout: 0, Count: 10}); err != nil {
		return err
	}

  return nil
}

func check(err error){
  if err != nil {
    errw := errors.Wrap(err,1)
    log.WithFields(log.Fields{"error": errw, "stack": errw.ErrorStack()}).Fatal("Error running test")
  }
}

//func TestRunMapPages(t *testing.T){
//    maps := make(map[uint64]([]byte))
//    maps[0x84ce00] = make([]byte, 25160)
//
//    ev := be.NewEventsToMinHash()
//    config := be.Config{
//      MaxTraceInstructionCount: 100,
//      MaxTraceTime:             0,
//      MaxTracePages:            50,
//      Arch:                     uc.ARCH_X86,
//      Mode:                     uc.MODE_64,
//      EventHandler:             ev,
//    }
//    em, _ := be.NewEmulator(maps, config)
//    check(em.WriteMemory(maps))
//}

//func TestRunMapPages2(t *testing.T){
//	mu, err := uc.NewUnicorn(uc.ARCH_X86, uc.MODE_64)
//  check(err)
//  data := make([]byte, 25160)
//  offset := uint64(0x84ce00)
//  poffset := offset - (offset%4096)
//  dlen := uint64(len(data))
//  pend_offset := offset + dlen + 4096-(offset+dlen)%4096
//  plen := pend_offset - poffset
//  log.WithFields(log.Fields{"offset": offset, "page offset": poffset, "page length": plen, "data length": dlen}).Error("Mapping")
//	check( mu.MemMap(poffset, plen) )
//  check( mu.MemWrite(offset, data))
//}

func TestStateBetweenRuns(t *testing.T){
  data := []byte{93, 195, 85, 72, 137, 229, 72, 139, 5, 52, 7, 67, 0, 72, 139, 64, 64, 255, 208, 93, 195, 85, 72, 137}
  offset := uint64(0x422f96)
	mu, err := uc.NewUnicorn(uc.ARCH_X86, uc.MODE_64)
  check( err )
  check( addHooks(mu) )
	check( mu.MemMap(offset - (offset%4096), 4096) )
	check( mu.MemMapProt(0, 0x4000, uc.PROT_READ|uc.PROT_WRITE) )
  check( mu.MemWrite(offset, data) )
  check( mu.RegWrite(uc.X86_REG_RAX, 0x1337) )
  check( mu.StartWithOptions(offset, ^uint64(0), &uc.UcOptions{Timeout: 0, Count: 10}) )
  t.Fail()
}

//func TestRunMapUnmap(t *testing.T){
//	mu, err := uc.NewUnicorn(uc.ARCH_X86, uc.MODE_64)
//  check(err)
//  //check(addHooks(mu))
//
//	check( mu.MemMap(0x0000, 0x4000) )
//	check( mu.MemMap(0x0000, 0x1000) )
//	check( mu.MemUnmap(0x2000, 0x2000) )
//
//  //err = mu.StartWithOptions(0x6000, 0x1500, &uc.UcOptions{Timeout: 0, Count: 10})
//  check( err )
//}

//func TestRunExample(t *testing.T) {
//  fmt.Println("foo")
//	if err := run(); err != nil {
//		fmt.Println(err)
//	}
//  t.Fail()
//}
