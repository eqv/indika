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
  last_valid_read uint64 //will be needed to weed out the additional reads reported due to missalignment
  last_valid_write uint64 //will be needed to weed out the additional writes reported due to missalignment
  last_valid_write_size uint64 //will be needed to weed out the additional writes reported due to missalignment
}

type EventHandler interface {
	WriteEvent(em *Emulator, addr, value uint64)
	ReadEvent(em *Emulator, addr uint64)
	BlockEvent(em *Emulator, start_addr, end_addr uint64)
	SyscallEvent(em *Emulator,number uint64)
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
		for page := addr - (addr % pagesize); ; page += pagesize {
			if err := s.mu.MemMap(page, pagesize); err != nil {
				return wrap(err)
			}
			if page+pagesize >= addr+uint64(len(val)) {
				break
			}
		}
		log.WithFields(log.Fields{"addr": addr, "length": len(val)}).Debug("Write Memory Content")
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
		if err := s.ResetWorkingSet(); err != nil {
			return err
		}
		if err := s.ResetRegisters(); err != nil {
			return err
		}
		if err := s.ResetMemoryImage(); err != nil {
			return err
		}
		s.CurrentTrace = nil
	}
	return nil
}

func (s *Emulator) handle_emulator_error(err error) *errors.Error {
	if err == nil {
		return nil
	}
	uc_err := err.(uc.UcError)
	if uc_err == uc.ERR_INSN_INVALID {
		ip, _ := s.mu.RegRead(uc.X86_REG_RIP)
		s.Config.EventHandler.InvalidInstructionEvent(s, ip)
		return nil
	}
	return wrap(err)
}

func (s *Emulator) RunOneTrace(addr uint64, end uint64) *errors.Error { //TODO is ^uint64(0) the right way to ignore the end?
	if addr >= end {
		return wrap(errors.New(fmt.Sprintf("Empty BB from %x to %x", addr, end)))
	}
	opt := uc.UcOptions{Timeout: s.Config.MaxTraceTime, Count: s.Config.MaxTraceInstructionCount}
	err := s.mu.StartWithOptions(addr, end, &opt)
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
      is_below_current_stack := addr >= stack
      return is_above_initial_stack && is_below_current_stack
}

func (s *Emulator) handleMemoryEvent(access int, addr uint64, size int, value int64){
    ip,_ := s.mu.RegRead(uc.X86_REG_RIP)
    if size <= 0 { panic("invalid write") }
		if access == uc.MEM_WRITE {
      if s.should_ignore_write(addr,size){
        log.WithFields(log.Fields{"at": ip, "addr": addr, "value": value, "size": size}).Debug("Skip Write Event")
        return
      }
      s.last_valid_write = addr
      s.last_valid_write_size = uint64(size)
      log.WithFields(log.Fields{"at": ip, "addr": addr, "value": value, "size": size}).Debug("Write Event")
			s.Config.EventHandler.WriteEvent(s,addr, uint64(value))
		} else {
      if s.should_ignore_read(addr,size) {
          log.WithFields(log.Fields{"at": ip,"addr": addr, "value": value, "size": size}).Debug("Skip Read Event")
          return
      }
      s.last_valid_read = addr

      log.WithFields(log.Fields{"at": ip,"addr": addr, "value": value, "size": size}).Debug("Read Event")
			s.Config.EventHandler.ReadEvent(s,addr)
		}
}


func (s *Emulator) addHooks() *errors.Error {

	_, err := s.mu.HookAdd(uc.HOOK_BLOCK, func(mu uc.Unicorn, addr uint64, size uint32) {
		if size < 1 {
			log.WithFields( log.Fields{"addr": addr, "size": size} ).Error( "Empty BB" )
		}
		s.CurrentTrace.AddBlockRange(addr, addr+uint64(size)-1)
		log.WithFields(log.Fields{"from": addr, "to": addr + uint64(size)}).Debug( "BB visited" )
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
		log.WithFields(log.Fields{"addr": addr, "size": size}).Debug("invalid memory access")
		err2 := s.WorkingSet.Map(addr, uint64(size), mu)
		if err2 != nil {
			if err2.Err.(uc.UcError) == uc.ERR_WRITE_UNMAPPED {
				log.WithFields(log.Fields{"error": err2, "stack": err2.ErrorStack()}).Warn("WRITE TO UNMAPPED MEMORY")
			} else {
				log.WithFields(log.Fields{"addr": addr, "size": size, "error": err2, "stack": err2.ErrorStack()}).Fatal("Error Mapping page")
			}
		}
		return true
	})
	if err != nil {
		return wrap(err)
	}

	_, err = s.mu.HookAdd(uc.HOOK_INSN, func(mu uc.Unicorn) {
		rax, _ := mu.RegRead(uc.X86_REG_RAX)
		s.Config.EventHandler.SyscallEvent(s,rax)
    log.WithFields(log.Fields{"num": rax}).Debug("Syscall")
	}, uc.X86_INS_SYSCALL)
	if err != nil {
		return wrap(err)
	}

//  hook_inst_int := func (mu uc.Unicorn){
//		rax, _ := mu.RegRead(uc.X86_REG_RAX)
//		s.Config.EventHandler.SyscallEvent(s,rax)
//    log.WithFields(log.Fields{"num": rax}).Debug("Interrupt")
//	}

//	_, err = s.mu.HookAdd(uc.HOOK_INSN, hook_inst_int, uc.X86_INS_INT)
//	if err != nil {
//		return wrap(err)
//	}

//	s.mu.HookAdd(uc.HOOK_CODE, func(mu uc.Unicorn, addr uint64, size uint32) {
//    rax,_ := s.mu.RegRead(uc.X86_REG_RAX)
//    log.WithFields(log.Fields{"at": addr, "size": size, "RAX": rax}).Debug("Instruction")
//	})

	return nil
}
