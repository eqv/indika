package blanket_emulator

import (
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/go-errors/errors"
	ds "github.com/ranmrdrakono/indika/data_structures"
	"github.com/ranmrdrakono/indika/arch"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
	"sort"
)

// Ignore reads/writes in the first 128 bytes above the stack pointer because some times if there are no further function calls, the
// stackpointer is not adjusted to the current stack frame and local variables are actually stored outside of the
// current stack frame
const ignore_stackframe_above_stack_pointer_size = 128

//Ignore reads/writes below the initial stack pointer. We need to ignore some amount below the stack pointer, since
//there will be no correct stacksetup if we start from some intermediate basic block. Leave/Return will then read from an
//address below the stackframe
const ignore_stackframe_below_initial_stack_pointer_size = 50 * 8

// the returnaddress will differ, based on wether the trace encountert a valid stack frame epilog (in which case return
// will jump to the value stored in the value addressed by the initial rsp) or not (in which case the function will
// return to a value stored signifikant lower on the stack). Since Optimization will often remove the entire need for a
// stackframe, this produces massively differen results.
const ignore_invalid_instructions_after_return = true

//any read/write/jmp that points into parts of the loaded binary will be replaced by the number of previous such memory
//accesses+1 + 0xe1f0ff5e70000
const resolve_static_addresses = true

type Emulator struct {
	CurrentTrace             *Trace
	WorkingSet               *WorkingSet
  Env                      Environment
	Config                   Config
  Events                   *EventSet
	mu                       uc.Unicorn
	codepages                map[uint64]([]byte)
	binaryContentPages       map[ds.Range]bool
	staticAddresses          map[uint64]uint64
	last_instruction_was_ret bool
}

type Config struct {
	MaxTraceInstructionCount uint64
	MaxTraceTime             uint64
	MaxTracePages            int
	Arch                     arch.Arch
	Mode                     int
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


func (s *Emulator) WriteEvent(addr, value uint64) {
	s.Events.Add(WriteEvent{Addr: addr, Value: value})
}

func (s *Emulator) ReadEvent(addr uint64) {
	s.Events.Add(ReadEvent(addr))
}

func (s *Emulator) SyscallEvent(number uint64) {
	s.Events.Add(SyscallEvent(number))
}

func (s *Emulator) ReturnEvent(number uint64) {
	s.Events.Add(ReturnEvent(number))
}

func (s *Emulator) InvalidInstructionEvent(offset uint64) {
	s.Events.Add(InvalidInstructionEvent(offset))
}

func mapLoadableRangeToStarts(mem map[ds.Range]*ds.MappedRegion) map[uint64][]byte {
	res := make(map[uint64][]byte)
	for key, val := range mem {
		if val.Loaded {
			res[key.From] = (*val).Data
		}
	}
	return res
}

func getSetOfOriginalContentPages(mem map[ds.Range]*ds.MappedRegion) map[ds.Range]bool {
	res := make(map[ds.Range]bool)
	for key, _ := range mem {
		res[key] = true
	}
	return res
}

func NewEmulator(mem map[ds.Range]*ds.MappedRegion, conf Config, env Environment) *Emulator {
	res := new(Emulator)
	res.Config = conf
  res.Env = env
	res.codepages = mapLoadableRangeToStarts(mem)
	res.binaryContentPages = getSetOfOriginalContentPages(mem)
	res.staticAddresses = make(map[uint64]uint64)
  res.Events = NewEventSet()
	return res
}

func (s *Emulator) CreateUnicorn() *errors.Error {
	if s.mu != nil {
		s.Close()
	}
	mu, err2 := uc.NewUnicorn(s.Config.Arch.ToUnicornArchDescription(), s.Config.Arch.ToUnicornModeDescription())
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
		page_end := data_end + 4096 - data_end%4096
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

func (s *Emulator) FullBlanket(blocks_to_visit map[uint64]ds.BB) *errors.Error {
	max_blocks_number := len(blocks_to_visit)

	for i := 0; i < max_blocks_number; i++ {
		s.CurrentTrace = NewTrace(&blocks_to_visit)
		addr, should_continue := s.CurrentTrace.FirstUnseenBlock()

		if !should_continue {
			return nil
		}

		if err := s.RunOneTrace(addr); err != nil {
			return wrap(err)
		}

		s.CurrentTrace = nil
	}
  if len(blocks_to_visit)== 0{
    return nil
  }
	return errors.Errorf("Failed to run full blanket, remaining: %d (of %d)", len(blocks_to_visit), max_blocks_number)
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

	if uc_err == uc.ERR_INSN_INVALID || uc_err == uc.ERR_FETCH_UNMAPPED || uc_err == uc.ERR_FETCH_PROT {
		if ignore_invalid_instructions_after_return && s.last_instruction_was_ret {
			log.WithFields(log.Fields{"at": hex(ip)}).Debug("Ignored Invalid Instruction Event")
			return nil
		}
		log.WithFields(log.Fields{"at": hex(ip)}).Info("Invalid Instruction Event")
		s.InvalidInstructionEvent(ip)
		return nil
	}
	return wrap(err)
}

func (s *Emulator) RunOneTrace(addr uint64) *errors.Error { //TODO is ^uint64(0) the right way to ignore the end?
	cerr := s.CreateUnicorn()
	if cerr != nil {
		return cerr
	}

	log.WithFields(log.Fields{"addr": hex(addr)}).Debug("Run One Trace")
	opt := uc.UcOptions{Timeout: s.Config.MaxTraceTime, Count: s.Config.MaxTraceInstructionCount}
	err := s.mu.StartWithOptions(addr, ^uint64(0), &opt)
	log.WithFields(log.Fields{"addr": hex(addr)}).Debug("Finished One Trace")
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

  for _,reg := range s.Config.Arch.GetRegisters() {
    if err := s.mu.RegWrite(reg, 0); err != nil {
      return wrap(err)
    }
  }

	if err := s.mu.RegWrite(uc.X86_REG_RAX, s.Env.GetReg(1)); err != nil {
		return wrap(err)
	}
	if err := s.mu.RegWrite(uc.X86_REG_RBX, s.Env.GetReg(2)); err != nil {
		return wrap(err)
	}
	if err := s.mu.RegWrite(uc.X86_REG_RDX, s.Env.GetReg(3)); err != nil {
		return wrap(err)
	}
	if err := s.mu.RegWrite(uc.X86_REG_RCX, s.Env.GetReg(4)); err != nil {
		return wrap(err)
	}
	if err := s.mu.RegWrite(uc.X86_REG_RSP, s.Env.GetReg(REG_STACK)-s.Env.GetReg(REG_STACK)%4096); err != nil {
		return wrap(err)
	}
	if err := s.mu.RegWrite(uc.X86_REG_RBP, s.Env.GetReg(REG_STACK)-s.Env.GetReg(REG_STACK)%4096+50*8); err != nil {
		return wrap(err)
	}
	if err := s.mu.RegWrite(uc.X86_REG_RSI, s.Env.GetReg(7)); err != nil {
		return wrap(err)
	}

	if err := s.mu.RegWrite(uc.X86_REG_RDI, s.Env.GetReg(8)); err != nil {
		return wrap(err)
	}

	return nil
}

func (s *Emulator) is_in_stack_frame(addr uint64) bool {
	is_above_initial_stack := addr <= s.Env.GetReg(REG_STACK)+ignore_stackframe_below_initial_stack_pointer_size
	stack, _ := s.mu.RegRead(s.Config.Arch.GetRegStack())
	is_below_current_stack := addr >= stack-ignore_stackframe_above_stack_pointer_size
	return is_above_initial_stack && is_below_current_stack
}

func (s *Emulator) should_ignore_read(addr uint64, size int) bool {
	return s.is_in_stack_frame(addr)
}

func (s *Emulator) should_ignore_write(addr uint64, size int) bool {
	return s.is_in_stack_frame(addr)
}

func (s *Emulator) isStaticAddr(addr uint64) bool {

	if !resolve_static_addresses {
		return false
	}

	for prange, _ := range s.binaryContentPages {
		if prange.Include(addr) {
			return true
		}
	}
	return false
}

func (s *Emulator) resolve_static(addr uint64) uint64 {
	if !s.isStaticAddr(addr) {
		return addr
	}

	if val, ok := s.staticAddresses[addr]; ok {
		return val
	}

  //replace address with fake elfoffset to reduce noise created by different static addresses
	next_val := uint64(0xe1f0ff5e70000) + uint64(len(s.staticAddresses)) + 1
	s.staticAddresses[addr] = next_val
	return next_val
}

func (s *Emulator) handleMemoryEvent(access int, addr uint64, size int, ivalue int64) {
	addr = s.resolve_static(addr)
	val := s.resolve_static(uint64(ivalue))
	ip, _ := s.mu.RegRead(uc.X86_REG_RIP)

	if size <= 0 {
		panic("invalid write")
	}

	if access == uc.MEM_WRITE {
		if s.should_ignore_write(addr, size) {
			log.WithFields(log.Fields{"at": hex(ip), "addr": hex(addr), "value": val, "size": size}).Debug("Skip Write Event")
			return
		}

		log.WithFields(log.Fields{"at": hex(ip), "addr": hex(addr), "value": val, "size": size}).Info("Write Event")
		s.WriteEvent(addr, val)
	} else {

		if s.should_ignore_read(addr, size) {
			log.WithFields(log.Fields{"at": hex(ip), "addr": hex(addr), "value": val, "size": size}).Debug("Skip Read Event")
			return
		}

		log.WithFields(log.Fields{"at": hex(ip), "addr": hex(addr), "value": val, "size": size}).Info("Read Event")
		s.ReadEvent( addr)
	}
}

func hex(val uint64) string {
	return fmt.Sprintf("0x%x", val)
}

func (s *Emulator) OnBlock(addr uint64, size uint32){
		if size < 1 {
			log.WithFields(log.Fields{"addr": addr, "size": size}).Debug("Empty BB")
			s.CurrentTrace.AddBlockRangeVisited(addr, addr)
		}
		s.CurrentTrace.AddBlockRangeVisited(addr, addr+uint64(size)-1)
		log.WithFields(log.Fields{"from": hex(addr), "to": hex(addr + uint64(size))}).Debug("BB visited")
}

func (s *Emulator) OnInvalidMem(access int, addr uint64, size int, value int64) bool {
		log.WithFields(log.Fields{"addr": hex(addr), "size": size}).Debug("invalid memory access")
		if access == uc.MEM_FETCH_UNMAPPED || access == uc.MEM_FETCH_PROT {
			return false
		}

		if access == uc.MEM_READ_UNMAPPED || access == uc.MEM_WRITE_UNMAPPED {
			err := s.WorkingSet.Map(addr, uint64(size), s)
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
}

func (s *Emulator) addHooks() *errors.Error {

	_, err := s.mu.HookAdd(uc.HOOK_BLOCK, func(mu uc.Unicorn, addr uint64, size uint32) {  
    s.OnBlock(addr, size) 
  })
	if err != nil {
		return wrap(err)
	}

	_, err = s.mu.HookAdd(uc.HOOK_MEM_READ|uc.HOOK_MEM_WRITE, func(mu uc.Unicorn, access int, addr uint64, size int, value int64) {
		s.handleMemoryEvent(access, addr, size, value)
	})
	if err != nil {
		return wrap(err)
	}

	invalid := uc.HOOK_MEM_READ_INVALID | uc.HOOK_MEM_WRITE_INVALID | uc.HOOK_MEM_FETCH_INVALID

	_, err = s.mu.HookAdd(invalid, func(mu uc.Unicorn, access int, addr uint64, size int, value int64) bool {
    return s.OnInvalidMem(access, addr, size, value)
	})

	if err != nil {
		return wrap(err)
	}

	hook_inst_sys := func(mu uc.Unicorn) {
		//rax, _ := mu.RegRead(uc.X86_REG_RAX)
		//s.SyscallEvent(s,rax)
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

	s.mu.HookAdd(uc.HOOK_CODE, func(mu uc.Unicorn, addr uint64, size uint32) {
		rax, _ := s.mu.RegRead(s.Config.Arch.GetRegRet())
		rsp, _ := s.mu.RegRead(s.Config.Arch.GetRegStack())
		rip, _ := s.mu.RegRead(s.Config.Arch.GetRegIP())
		mem, _ := s.mu.MemRead(rip, 16)
		s.last_instruction_was_ret = false
		if s.Config.Arch.IsRet(mem) { // special treatment for RET instruction
			s.ReturnEvent(rax)
			log.WithFields(log.Fields{"at": hex(addr), "rax": hex(rax)}).Info("Ret Event")
			s.last_instruction_was_ret = true
		}
		log.WithFields(log.Fields{"at": hex(addr), "size": size, "rax": hex(rax), "rsp": hex(rsp)}).Debug("Instruction")
	})

	return nil
}
