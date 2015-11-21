package blanket_emulator

import (
	log "github.com/Sirupsen/logrus"
	"github.com/go-errors/errors"
	ds "github.com/ranmrdrakono/indika/data_structures"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
)

type EventHandler interface {
	WriteEvent(addr, value uint64)
	ReadEvent(addr uint64)
	BlockEvent(start_addr, end_addr uint64)
	SyscallEvent(number uint64)
}

type Emulator struct {
	CurrentTrace *Trace
	WorkingSet   *WorkingSet
	Config       Config
	mu           uc.Unicorn
	codepages    map[uint64]([]byte)
}

type Config struct {
	MaxTraceInstructionCount uint64
	MaxTraceTime             uint64
	MaxTracePages            int
	Arch                     int
	Mode                     int
	EventHandler             EventHandler
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

func NewEmulator(codepages map[uint64]([]byte), conf Config) (*Emulator, *errors.Error) {
	res := new(Emulator)
	res.Config = conf
	res.codepages = codepages
	res.WorkingSet = NewWorkingSet(conf.MaxTracePages)
	mu, err2 := uc.NewUnicorn(conf.Arch, conf.Mode)
	if err2 != nil {
		return nil, errors.Wrap(err2, 0)
	}
	res.mu = mu
	err := res.addHooks()
	if err != nil {
		return nil, errors.Wrap(err, 0)
	}
	if err = res.WriteMemory(codepages); err != nil {
		return nil, errors.Wrap(err, 0)
	}
	if err = res.ResetRegisters(); err != nil {
		return nil, errors.Wrap(err, 0)
	}

	return res, nil
}

func check_consistency(codepages map[uint64]([]byte)) {
	for addr, _ := range codepages {
		if addr%pagesize != 0 {
			err := errors.Errorf("broken alignment")
			log.WithFields(log.Fields{"error": err, "stack": err.ErrorStack(), "addr": addr}).Fatal("Broken Page Alignment")
		}
	}
}

func (s *Emulator) WriteMemory(codepages map[uint64]([]byte)) *errors.Error {
	for addr, val := range codepages {
		for page := addr - (addr % pagesize); ; page += pagesize {
			if err := s.mu.MemMap(page, pagesize); err != nil {
				return wrap(err)
			}
			if page+pagesize >= addr+uint64(len(val)) {
				break
			}
		}
		if err := s.mu.MemWrite(addr, val); err != nil {
			return wrap(err)
		}
	}
	return nil
}

func getLastBlockEndFromSet(blocks_to_visit *map[ds.Range]bool) uint64 {
	res := uint64(0)
	for rng := range *blocks_to_visit {
		if rng.To > res {
			res = rng.To
		}
	}
	return res
}

func (s *Emulator) FullBlanket(blocks_to_visit map[ds.Range]bool) *errors.Error {
	last_block_end := getLastBlockEndFromSet(&blocks_to_visit)
	for {
		s.CurrentTrace = NewTrace(&blocks_to_visit)
		addr, should_continue := s.CurrentTrace.FirstUnseenBlock()
		if !should_continue {
			return nil
		}
		if err := s.RunOneTrace(addr, last_block_end); err != nil {
			return wrap(err)
		}
		if err := s.WorkingSet.Clear(s.mu); err != nil {
			return wrap(err)
		}
		s.CurrentTrace = nil
	}
	return nil
}

func (s *Emulator) RunOneTrace(addr uint64, end uint64) *errors.Error { //TODO is ^uint64(0) the right way to ignore the end?
	opt := uc.UcOptions{Timeout: s.Config.MaxTraceTime, Count: s.Config.MaxTraceInstructionCount}
	if err := s.mu.StartWithOptions(addr, end, &opt); err != nil {
		return wrap(err)
	}
	return nil
}

func (s *Emulator) ResetWorkingSet() *errors.Error {
	return s.WorkingSet.Clear(s.mu)
}

func (s *Emulator) ResetMemoryImage() *errors.Error {
	return s.WriteMemory(s.codepages)
}

func (s *Emulator) ResetRegisters() *errors.Error {
	if err := s.mu.RegWrite(uc.X86_REG_RDX, GetReg(3)); err != nil {
		return wrap(err)
	}
	return nil
}

func (s *Emulator) addHooks() *errors.Error {

	_, err := s.mu.HookAdd(uc.HOOK_BLOCK, func(mu uc.Unicorn, addr uint64, size uint32) {
		s.CurrentTrace.AddBlockRange(addr, addr+uint64(size))
	})
	if err != nil {
		return wrap(err)
	}

	_, err = s.mu.HookAdd(uc.HOOK_MEM_READ|uc.HOOK_MEM_WRITE, func(mu uc.Unicorn, access int, addr uint64, size int, value int64) {
		if access == uc.MEM_WRITE {
			s.Config.EventHandler.WriteEvent(addr, uint64(value))
		} else {
			s.Config.EventHandler.ReadEvent(addr)
		}
	})
	if err != nil {
		return wrap(err)
	}

	invalid := uc.HOOK_MEM_READ_INVALID | uc.HOOK_MEM_WRITE_INVALID | uc.HOOK_MEM_FETCH_INVALID
	_, err = s.mu.HookAdd(invalid, func(mu uc.Unicorn, access int, addr uint64, size int, value int64) bool {
		s.WorkingSet.Map(addr, uint64(size), mu)
		return true
	})
	if err != nil {
		return wrap(err)
	}

	_, err = s.mu.HookAdd(uc.HOOK_INSN, func(mu uc.Unicorn) {
		rax, _ := mu.RegRead(uc.X86_REG_RAX)
		s.Config.EventHandler.SyscallEvent(rax)
	}, uc.X86_INS_SYSCALL)
	if err != nil {
		return wrap(err)
	}
	return nil
}
