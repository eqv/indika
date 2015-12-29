package blanket_emulator

import (
	log "github.com/Sirupsen/logrus"
	"github.com/go-errors/errors"
	ds "github.com/ranmrdrakono/indika/data_structures"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
	"sort"
  "fmt"
)


type Emulator struct {
	CurrentTrace *Trace
	WorkingSet   *WorkingSet
	Config       Config
	mu           uc.Unicorn
	codepages    map[uint64]([]byte)
	binaryContentPages    map[ds.Range]bool
}

type EventHandler interface {
	WriteEvent(em *Emulator, addr, value uint64)
	ReadEvent(em *Emulator, addr uint64)
	StaticWriteEvent(em *Emulator, addr, value uint64)
	StaticReadEvent(em *Emulator, addr uint64)
	BlockEvent(em *Emulator, start_addr, end_addr uint64)
	SyscallEvent(em *Emulator,number uint64)
	ReturnEvent(em *Emulator,number uint64)
	InvalidInstructionEvent(em *Emulator, addr uint64)
}

type Config struct {
	MaxTraceInstructionCount uint64
	MaxTraceTime             uint64
	MaxTracePages            int
	Arch                     int
	Mode                     int
	EventHandler             EventHandler
}

const REG_STACK = 5

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


func mapKeysRangeToStarts(mem map[ds.Range]*ds.MappedRegion) map[uint64][]byte {
	res := make(map[uint64][]byte)
	for key, val := range mem {
		res[key.From] = (*val).Data
	}
	return res
}

func getSetOfOriginalContentPages(mem map[ds.Range]*ds.MappedRegion) map[ds.Range]bool{
	res := make(map[ds.Range]bool)
  for key, _ := range mem {
		res[key] = true
	}
	return res
}

func NewEmulator(mem map[ds.Range]*ds.MappedRegion, conf Config) *Emulator {
	res := new(Emulator)
	res.Config = conf
	res.codepages =mapKeysRangeToStarts(mem)
  res.binaryContentPages = getSetOfOriginalContentPages(mem)
	return res
}

func (s *Emulator) CreateUnicorn() *errors.Error {
  if s.mu != nil {
    s.Close()
  }
	mu, err2 := uc.NewUnicorn(s.Config.Arch, s.Config.Mode)
	s.WorkingSet = NewWorkingSet(s.Config.MaxTracePages)
	if err2 != nil {
		return errors.Wrap(err2, 0)
	}
	s.mu = mu
	err := s.addHooks()
	if err != nil {
		return errors.Wrap(err, 0)
	}

  if err := s.ResetMemoryImage(); err != nil {
    return err
  }
  if err := s.ResetWorkingSet(); err != nil {
    return err
  }
  if err := s.ResetRegisters(); err != nil {
    return err
  }
  return nil
}

func (s *Emulator) Close() *errors.Error {
    mu := s.mu
    s.mu = nil
	  return wrap(mu.Close())
}

func check_consistency(codepages map[uint64]([]byte)) {
	for addr, _ := range codepages {
		if addr%pagesize != 0 {
			err := errors.Errorf("broken alignment")
			log.WithFields(log.Fields{"error": err, "stack": err.ErrorStack(), "addr": addr}).Fatal("Broken Page Alignment")
		}
	}
}

type UIntArray ([]uint64)

func (s UIntArray) Len() int           { return len(s) }
func (s UIntArray) Swap(i, j int)      { t := s[i]; s[i] = s[j]; s[j] = t }
func (s UIntArray) Less(i, j int) bool { return s[i] > s[j] }

func get_addresses_from_codepages(codepages map[uint64]([]byte)) []uint64 {
	res := make([]uint64, len(codepages))
	i := 0
	for key, _ := range codepages {
		res[i] = key
		i += 1
	}
	sort.Sort(UIntArray(res))
	return res
}

func (s *Emulator) WriteMemory(codepages map[uint64]([]byte)) *errors.Error {
	for _, addr := range get_addresses_from_codepages(codepages) {
		val := codepages[addr]
    data_end := addr + uint64(len(val))
    page_start := addr - (addr % pagesize)
    page_end := data_end + 4096 - data_end %4096
    page_size := page_end - page_start
    s.mu.MemUnmap(page_start, page_size)
    log.WithFields(log.Fields{"addr": hex(page_start), "length": page_size}).Debug("Map Memory")
    if err := s.mu.MemMapProt(page_start, page_size, uc.PROT_WRITE); err != nil {
      return wrap(err)
    }
    log.WithFields(log.Fields{"addr": hex(addr), "length": len(val)}).Debug("Write Memory Content")
    if err := s.mu.MemWrite(addr, val); err != nil {
      return wrap(err)
    }
    if err := s.mu.MemProtect(page_start, page_size, uc.PROT_READ|uc.PROT_EXEC); err != nil {
      return wrap(err)
    }
	}
	return nil
}


func (s *Emulator) FullBlanket(blocks_to_visit map[ds.Range]bool) *errors.Error {
  max_blocks_number := len(blocks_to_visit)+5

  for i := 0; i < max_blocks_number; i++ {
		s.CurrentTrace = NewTrace(&blocks_to_visit)
		addr, should_continue := s.CurrentTrace.FirstUnseenBlock()

		if !should_continue {
			return nil
		}

		if err := s.RunOneTrace(addr, ^uint64(0)); err != nil {
			return wrap(err)
		}

		s.CurrentTrace = nil
	}
  return errors.Errorf("Failed to run full blanket, remaining: %d (of %d)" , len(blocks_to_visit), max_blocks_number)
}

func (s *Emulator) handle_emulator_error(err error) *errors.Error {
	if err == nil {
		return nil
	}
	uc_err := err.(uc.UcError)
	ip, _ := s.mu.RegRead(uc.X86_REG_RIP)
  log.WithFields(log.Fields{"err": err, "ip": hex(ip)}).Debug("Emulator Error Occured")

  if uc_err == uc.ERR_READ_PROT || uc_err == uc.ERR_WRITE_PROT {
    return nil //fix me and make it trace accesses
  }

	if uc_err == uc.ERR_INSN_INVALID  || uc_err == uc.ERR_FETCH_UNMAPPED || uc_err == uc.ERR_FETCH_PROT{
		s.Config.EventHandler.InvalidInstructionEvent(s, ip)
		return nil
	}
	return wrap(err)
}

func (s *Emulator) RunOneTrace(addr uint64, end uint64) *errors.Error { //TODO is ^uint64(0) the right way to ignore the end?
  cerr := s.CreateUnicorn()
  if cerr != nil { return cerr}
	if addr >= end {
		return wrap(errors.New(fmt.Sprintf("Empty BB from %x to %x", hex(addr), hex(end))))
	}

  dumpstart := 0x422f96
  dumpend := 0x422fa9
  mem,err2 := s.mu.MemRead(addr, pagesize)
	if err2 != nil {
		return wrap(err2)
	}
  log.WithFields(log.Fields{"addr": addr, "memdump": mem[0:dumpend-dumpstart+5]}).Debug("Memory read")

  log.WithFields(log.Fields{"addr": hex(addr), "to": hex(end)}).Debug("Run One Trace")
	opt := uc.UcOptions{Timeout: s.Config.MaxTraceTime, Count: s.Config.MaxTraceInstructionCount}
  err := s.mu.StartWithOptions(addr, end, &opt)
  log.WithFields(log.Fields{"addr": hex(addr), "to": hex(end)}).Debug("Finished One Trace")
	return s.handle_emulator_error(err)
}

func (s *Emulator) ResetWorkingSet() *errors.Error {
	return s.WorkingSet.Clear(s.mu)
}

func (s *Emulator) ResetMemoryImage() *errors.Error {
	log.Debug("Reset Memory Image")
	return s.WriteMemory(s.codepages)
}

func (s *Emulator) ResetRegisters() *errors.Error {
	if err := s.mu.RegWrite(uc.X86_REG_RAX, GetReg(1)); err != nil {
		return wrap(err)
	}
	if err := s.mu.RegWrite(uc.X86_REG_RBX, GetReg(2)); err != nil {
		return wrap(err)
	}
	if err := s.mu.RegWrite(uc.X86_REG_RDX, GetReg(3)); err != nil {
		return wrap(err)
	}
	if err := s.mu.RegWrite(uc.X86_REG_RCX, GetReg(4)); err != nil {
		return wrap(err)
	}
	if err := s.mu.RegWrite(uc.X86_REG_RSP, GetReg(REG_STACK) - GetReg(REG_STACK)%4096); err != nil {
		return wrap(err)
	}
	if err := s.mu.RegWrite(uc.X86_REG_RBP, GetReg(REG_STACK) - GetReg(REG_STACK)%4096 + 50*8); err != nil {
		return wrap(err)
	}
	if err := s.mu.RegWrite(uc.X86_REG_RSI, GetReg(7)); err != nil {
		return wrap(err)
	}

	if err := s.mu.RegWrite(uc.X86_REG_RDI, GetReg(8)); err != nil {
		return wrap(err)
	}

	if err := s.mu.RegWrite(uc.X86_REG_EFLAGS   ,0); err != nil {return wrap(err)}
  if err := s.mu.RegWrite(uc.X86_REG_FPSW     ,0); err != nil {return wrap(err)} 
  if err := s.mu.RegWrite(uc.X86_REG_FS       ,0); err != nil {return wrap(err)} 
	if err := s.mu.RegWrite(uc.X86_REG_GS       ,0); err != nil {return wrap(err)}    
	if err := s.mu.RegWrite(uc.X86_REG_IP       ,0); err != nil {return wrap(err)}    
  if err:= s.mu.RegWrite(uc.X86_REG_SI        ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_SIL       ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_SP        ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_SPL       ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_SS        ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_CR0       ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_CR1       ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_CR2       ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_CR3       ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_CR4       ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_CR5       ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_CR6       ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_CR7       ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_CR8       ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_CR9       ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_CR10      ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_CR11      ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_CR12      ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_CR13      ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_CR14      ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_CR15      ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_DR0       ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_DR1       ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_DR2       ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_DR3       ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_DR4       ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_DR5       ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_DR6       ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_DR7       ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_DR8       ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_DR9       ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_DR10      ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_DR11      ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_DR12      ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_DR13      ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_DR14      ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_DR15      ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_FP0       ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_FP1       ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_FP2       ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_FP3       ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_FP4       ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_FP5       ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_FP6       ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_FP7       ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_K0        ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_K1        ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_K2        ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_K3        ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_K4        ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_K5        ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_K6        ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_K7        ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_MM0       ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_MM1       ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_MM2       ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_MM3       ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_MM4       ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_MM5       ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_MM6       ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_MM7       ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_R8        ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_R9        ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_R10       ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_R11       ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_R12       ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_R13       ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_R14       ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_R15       ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_ST0       ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_ST1       ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_ST2       ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_ST3       ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_ST4       ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_ST5       ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_ST6       ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_ST7       ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_XMM0      ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_XMM1      ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_XMM2      ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_XMM3      ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_XMM4      ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_XMM5      ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_XMM6      ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_XMM7      ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_XMM8      ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_XMM9      ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_XMM10     ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_XMM11     ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_XMM12     ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_XMM13     ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_XMM14     ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_XMM15     ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_XMM16     ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_XMM17     ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_XMM18     ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_XMM19     ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_XMM20     ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_XMM21     ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_XMM22     ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_XMM23     ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_XMM24     ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_XMM25     ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_XMM26     ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_XMM27     ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_XMM28     ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_XMM29     ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_XMM30     ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_XMM31     ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_YMM0      ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_YMM1      ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_YMM2      ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_YMM3      ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_YMM4      ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_YMM5      ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_YMM6      ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_YMM7      ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_YMM8      ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_YMM9      ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_YMM10     ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_YMM11     ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_YMM12     ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_YMM13     ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_YMM14     ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_YMM15     ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_YMM16     ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_YMM17     ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_YMM18     ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_YMM19     ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_YMM20     ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_YMM21     ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_YMM22     ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_YMM23     ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_YMM24     ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_YMM25     ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_YMM26     ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_YMM27     ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_YMM28     ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_YMM29     ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_YMM30     ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_YMM31     ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_ZMM0      ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_ZMM1      ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_ZMM2      ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_ZMM3      ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_ZMM4      ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_ZMM5      ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_ZMM6      ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_ZMM7      ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_ZMM8      ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_ZMM9      ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_ZMM10     ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_ZMM11     ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_ZMM12     ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_ZMM13     ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_ZMM14     ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_ZMM15     ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_ZMM16     ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_ZMM17     ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_ZMM18     ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_ZMM19     ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_ZMM20     ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_ZMM21     ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_ZMM22     ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_ZMM23     ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_ZMM24     ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_ZMM25     ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_ZMM26     ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_ZMM27     ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_ZMM28     ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_ZMM29     ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_ZMM30     ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_ZMM31     ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_R8B       ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_R9B       ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_R10B      ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_R11B      ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_R12B      ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_R13B      ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_R14B      ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_R15B      ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_R8D       ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_R9D       ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_R10D      ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_R11D      ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_R12D      ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_R13D      ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_R14D      ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_R15D      ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_R8W       ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_R9W       ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_R10W      ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_R11W      ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_R12W      ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_R13W      ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_R14W      ,0); err != nil {return wrap(err)}
	if err:= s.mu.RegWrite(uc.X86_REG_R15W      ,0); err != nil {return wrap(err)}
	return nil
}

func (s *Emulator) should_ignore_read(addr uint64, size int) bool {
      is_above_initial_stack := addr <= GetReg(REG_STACK)
      stack,_ := s.mu.RegRead(uc.X86_REG_RSP)
      is_below_current_stack := addr >= stack
      return is_above_initial_stack && is_below_current_stack
}

func (s *Emulator) should_ignore_write(addr uint64, size int) bool {
      is_above_initial_stack := addr <= GetReg(REG_STACK)
      stack,_ := s.mu.RegRead(uc.X86_REG_RSP)
      is_below_current_stack := addr >= stack-8
      return is_above_initial_stack && is_below_current_stack
}

func (s *Emulator) isStaticAddr(addr uint64) bool{
  for prange,_ := range s.binaryContentPages{
    if prange.Include(addr) {
      return true
    }
  }
  return false
}

func (s *Emulator) handleMemoryEvent(access int, addr uint64, size int, value int64){
    ip,_ := s.mu.RegRead(uc.X86_REG_RIP)
    if size <= 0 { panic("invalid write") }
		if access == uc.MEM_WRITE {
      if s.should_ignore_write(addr,size){
        log.WithFields(log.Fields{"at": hex(ip), "addr": hex(addr), "value": value, "size": size}).Debug("Skip Write Event")
        return
      }

      if s.isStaticAddr(addr){
        log.WithFields(log.Fields{"at": hex(ip),"addr": hex(addr), "value": value, "size": size}).Debug("Static Write Event")
        s.Config.EventHandler.StaticWriteEvent(s,addr, uint64(value))
      }else{
        log.WithFields(log.Fields{"at": hex(ip),"addr": hex(addr), "value": value, "size": size}).Debug("Write Event")
			  s.Config.EventHandler.WriteEvent(s,addr, uint64(value))
      }
		} else {

      if s.should_ignore_read(addr,size) {
          log.WithFields(log.Fields{"at": hex(ip),"addr": hex(addr), "value": value, "size": size}).Debug("Skip Read Event")
          return
      }

      if s.isStaticAddr(addr){
        log.WithFields(log.Fields{"at": hex(ip),"addr":hex(addr), "value": value, "size": size}).Debug("Static Read Event")
			  s.Config.EventHandler.StaticReadEvent(s,addr)
      }else{
        log.WithFields(log.Fields{"at": hex(ip),"addr": hex(addr), "value": value, "size": size}).Debug("Read Event")
			  s.Config.EventHandler.ReadEvent(s,addr)
      }
		}
}

func hex(val uint64) string{
  return fmt.Sprintf("0x%x",val)
}

func (s *Emulator) addHooks() *errors.Error {

	_, err := s.mu.HookAdd(uc.HOOK_BLOCK, func(mu uc.Unicorn, addr uint64, size uint32) {
		if size < 1 {
			log.WithFields( log.Fields{"addr": addr, "size": size} ).Debug( "Empty BB" )
      s.CurrentTrace.AddBlockRange(addr, addr)
		}
		s.CurrentTrace.AddBlockRange(addr, addr+uint64(size)-1)
		log.WithFields(log.Fields{"from": hex(addr), "to": hex(addr + uint64(size)) }).Debug( "BB visited" )
	})
	if err != nil {
		return wrap(err)
	}

	_, err = s.mu.HookAdd(uc.HOOK_MEM_READ|uc.HOOK_MEM_WRITE, func(mu uc.Unicorn, access int, addr uint64, size int, value int64) {
    s.handleMemoryEvent(access, addr, size, value);
	})
	if err != nil {
		return wrap(err)
	}

	invalid := uc.HOOK_MEM_READ_INVALID | uc.HOOK_MEM_WRITE_INVALID | uc.HOOK_MEM_FETCH_INVALID
	_, err = s.mu.HookAdd(invalid, func(mu uc.Unicorn, access int, addr uint64, size int, value int64) bool {
		log.WithFields(log.Fields{"addr": hex(addr), "size": size}).Debug("invalid memory access")

    if access == uc.MEM_FETCH_UNMAPPED || access == uc.MEM_FETCH_PROT {
      return false;
    }

    if access == uc.MEM_READ_UNMAPPED || access == uc.MEM_WRITE_UNMAPPED {
      err := s.WorkingSet.Map(addr, uint64(size), mu)
      if err != nil {
          log.WithFields(log.Fields{"addr": hex(addr), "size": size, "error": err, "stack": err.ErrorStack()}).Fatal("Error Mapping page")
          return false
      }
      return true
    }

    if access == uc.MEM_READ_PROT || access == uc.MEM_WRITE_PROT {
          return false
    }

    log.WithFields(log.Fields{"addr": hex(addr), "access": access, "size": size}).Error("Unhandled Memory Error")
    return false
	})

	if err != nil {
		return wrap(err)
	}

  hook_inst_sys := func (mu uc.Unicorn){
		//rax, _ := mu.RegRead(uc.X86_REG_RAX)
		//s.Config.EventHandler.SyscallEvent(s,rax)
    //log.WithFields(log.Fields{"num": rax}).Debug("Syscall/Interrupt")
	}

	_, err = s.mu.HookAdd(uc.HOOK_INSN, hook_inst_sys, uc.X86_INS_SYSCALL)
	if err != nil {
		return wrap(err)
	}

	//_, err = s.mu.HookAdd(uc.HOOK_INTR, hook_inst_sys)
	//if err != nil {
	//	return wrap(err)
	//}

  //hook_inst_ret := func (mu uc.Unicorn){
	//	rax, _ := mu.RegRead(uc.X86_REG_RAX)
	//	s.Config.EventHandler.ReturnEvent(s,rax)
  //  log.WithFields(log.Fields{"val": rax}).Debug("Return")
	//}

  //_, err = s.mu.HookAdd(uc.HOOK_INSN, hook_inst_ret, uc.X86_INS_RET)
  //if err != nil {
	//  return wrap(err)
  //}

	s.mu.HookAdd(uc.HOOK_CODE, func(mu uc.Unicorn, addr uint64, size uint32) {
    rax,_ := s.mu.RegRead(uc.X86_REG_RAX)
    rip,_ := s.mu.RegRead(uc.X86_REG_RIP)
    mem,_ := s.mu.MemRead(rip, 16)
    if mem[0] == 0xc3 { //RET instruction
        s.Config.EventHandler.ReturnEvent(s,rax)
        log.WithFields(log.Fields{"at": hex(addr), "rax": hex(rax)}).Debug("Ret Event")
    }
    log.WithFields(log.Fields{"at": hex(addr), "size": size, "rax": hex(rax)}).Debug("Instruction")
	})

	return nil
}
