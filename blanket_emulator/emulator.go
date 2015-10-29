package blanket_emulator

import (
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
	config       Config
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

func NewEmulator(codepages map[uint64]([]byte), conf Config) (*Emulator, error) {
	res := new(Emulator)
	res.config = conf
	res.codepages = codepages
	res.WorkingSet = NewWorkingSet(conf.MaxTracePages)
	mu, err := uc.NewUnicorn(conf.Arch, conf.Mode)
	if err != nil {
		return nil, err
	}
	res.mu = mu
	if err = res.addHooks(); err != nil {
		return nil, err
	}
	if err = res.WriteMemory(codepages); err != nil {
		return nil, err
	}
	if err = res.ResetRegisters(); err != nil {
		return nil, err
	}

	return res, nil
}

func (s *Emulator) WriteMemory(codepages map[uint64]([]byte)) error {
	for addr, val := range codepages {
		for page := addr; ; page += pagesize {
			if err := s.mu.MemMap(page, pagesize); err != nil {
				return err
			}
			if page+pagesize >= addr+uint64(len(val)) {
				break
			}
		}
		if err := s.mu.MemWrite(addr, val); err != nil {
			return err
		}
	}
	return nil
}

func getLastBlockEndFromSet(blocks_to_visit *map[BlockRange]bool) uint64 {
	res := uint64(0)
	for rng := range *blocks_to_visit {
		if rng.To > res {
			res = rng.To
		}
	}
	return res
}

func (s *Emulator) FullBlanket(blocks_to_visit map[BlockRange]bool) error {
	last_block_end := getLastBlockEndFromSet(&blocks_to_visit)
	for {
		s.CurrentTrace = NewTrace(&blocks_to_visit)
		addr, should_continue := s.CurrentTrace.FirstUnseenBlock()
		if !should_continue {
			return nil
		}
		if err := s.RunOneTrace(addr, last_block_end); err != nil {
			return err
		}
		if err := s.WorkingSet.Clear(s.mu); err != nil {
			return err
		}
		s.CurrentTrace = nil
	}
	return nil
}

func (s *Emulator) RunOneTrace(addr uint64, end uint64) error { //TODO is ^uint64(0) the right way to ignore the end?
	opt := uc.UcOptions{Timeout: s.config.MaxTraceTime, Count: s.config.MaxTraceInstructionCount}
	if err := s.mu.StartWithOptions(addr, end, &opt); err != nil {
		return err
	}
	return nil
}

func (s *Emulator) ResetWorkingSet() error {
	return s.WorkingSet.Clear(s.mu)
}

func (s *Emulator) ResetMemoryImage() error {
	return s.WriteMemory(s.codepages)
}

func (s *Emulator) ResetRegisters() error {
	if err := s.mu.RegWrite(uc.X86_REG_RDX, GetReg(3)); err != nil {
		return err
	}
	return nil
}

func (s *Emulator) addHooks() error {

	_, err := s.mu.HookAdd(uc.HOOK_BLOCK, func(mu uc.Unicorn, addr uint64, size uint32) {
		s.CurrentTrace.AddBlockRange(addr, addr+uint64(size))
	})
	if err != nil {
		return err
	}

	_, err = s.mu.HookAdd(uc.HOOK_MEM_READ|uc.HOOK_MEM_WRITE, func(mu uc.Unicorn, access int, addr uint64, size int, value int64) {
		if access == uc.MEM_WRITE {
			s.config.EventHandler.WriteEvent(addr, uint64(value))
		} else {
			s.config.EventHandler.ReadEvent(addr)
		}
	})
	if err != nil {
		return err
	}

	invalid := uc.HOOK_MEM_READ_INVALID | uc.HOOK_MEM_WRITE_INVALID | uc.HOOK_MEM_FETCH_INVALID
	_, err = s.mu.HookAdd(invalid, func(mu uc.Unicorn, access int, addr uint64, size int, value int64) bool {
		s.WorkingSet.Map(addr, uint64(size), mu)
		return true
	})
	if err != nil {
		return err
	}

	_, err = s.mu.HookAdd(uc.HOOK_INSN, func(mu uc.Unicorn) {
		rax, _ := mu.RegRead(uc.X86_REG_RAX)
		s.config.EventHandler.SyscallEvent(rax)
	}, uc.X86_INS_SYSCALL)
	if err != nil {
		return err
	}
	return nil
}
