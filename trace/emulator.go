package trace

import (
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
  "fmt"
)

type Disassembler interface{
  GetBlocks(addr uint64, codepages map[uint64]([]byte)) map[BlockRange]bool
}

type Emulator struct {
  CurrentTrace *Trace
  Events map[uint64]bool
  config Config
  blocks_to_visit map[BlockRange]bool
  mu uc.Unicorn
  last_block_end uint64
  codepages map[uint64]([]byte)
}

type Config struct {
  MaxTraceInstructionCount uint;
  MaxTraceTime uint;
  MaxTracePages int;
  Arch int
  Mode int
  Disassembler Disassembler
}

func NewEmulator(codepages map[uint64]([]byte), conf Config) (*Emulator, error){
  res := new(Emulator)
  res.config = conf
  res.codepages = codepages
  mu, err := uc.NewUnicorn(conf.Arch, conf.Mode)
  if err != nil {
    return nil,err
  }
  res.mu = mu
  if err = res.WriteMemory(codepages) ; err != nil {return nil, err}
  if err = res.WriteRegisters() ; err != nil {return nil, err}

  return res,nil
}

func (s* Emulator) WriteRegisters() error{
	if err := s.mu.RegWrite(uc.X86_REG_RDX, GetReg(3)); err != nil {
		return err
	}
  return nil
}

func (s* Emulator) WriteMemory(codepages map[uint64]([]byte))error{
  for addr,val := range codepages {
    for page := addr; ; page += pagesize {
      if err := s.mu.MemMap(page,pagesize); err!=nil {
        return err
      }
      if page + pagesize >= addr+uint64(len(val)) {break}
    }
    if err := s.mu.MemWrite(addr, val); err != nil {
      return err
    }
  }
  return nil
}

func (s* Emulator) GetLastBlockEnd() uint64 {
  res := uint64(0)
  for rng := range s.blocks_to_visit{
    if rng.To > res {res = rng.To}
  }
  return res
}

func (s *Emulator) Run(addr uint64) error{
  s.blocks_to_visit = s.config.Disassembler.GetBlocks(addr, s.codepages)
  s.last_block_end = s.GetLastBlockEnd()
  for ;; {
    s.CurrentTrace = NewTrace(s.config.MaxTracePages, &s.blocks_to_visit)
    addr,should_continue := s.CurrentTrace.FirstUnseenBlock();
    if !should_continue { return nil }
    if err := s.RunTrace(addr) ; err != nil { return err }
    s.CurrentTrace = nil
  }
}

func (s *Emulator) RunTrace(addr uint64) error{
	if err := s.mu.Start( addr, s.last_block_end ); err != nil {
		return err
	}
  err := s.CurrentTrace.WorkingSet.Clear(s.mu)
  return err
}

func (s* Emulator) WriteEvent(addr, val uint64){
  s.CurrentTrace.WriteEvent(addr,val);
}

func (s* Emulator) ReadEvent(addr uint64){
  s.CurrentTrace.ReadEvent(addr);
}

func (s* Emulator) BlockEvent(start_addr, end_addr uint64){
  s.CurrentTrace.AddBlockRange(start_addr, end_addr);
}

func (s* Emulator) SyscallEvent(num uint64){
  s.CurrentTrace.SyscallEvent(num);
}

func (s* Emulator) AddHooks() {

	s.mu.HookAdd(uc.HOOK_BLOCK, func(mu uc.Unicorn, addr uint64, size uint32) {
    s.CurrentTrace.AddBlockRange(addr, addr+uint64(size));
	})

	s.mu.HookAdd(uc.HOOK_MEM_READ|uc.HOOK_MEM_WRITE, func(mu uc.Unicorn, access int, addr uint64, size int, value int64) {
		if access == uc.MEM_WRITE {
      s.WriteEvent(addr,uint64(value));
		} else {
      s.ReadEvent(addr);
		}
	})

	invalid := uc.HOOK_MEM_READ_INVALID | uc.HOOK_MEM_WRITE_INVALID | uc.HOOK_MEM_FETCH_INVALID
	s.mu.HookAdd(invalid, func(mu uc.Unicorn, access int, addr uint64, size int, value int64) bool {
    s.CurrentTrace.WorkingSet.Map(addr, uint64(size), mu)
		return true
	})

	s.mu.HookAdd(uc.HOOK_INSN, func(mu uc.Unicorn) {
		rax, _ := mu.RegRead(uc.X86_REG_RAX)
    s.SyscallEvent(rax)
	}, uc.X86_INS_SYSCALL)
}

func (s *Emulator) GetMaxEventByHash(seed uint64) uint64{
  max_val := uint64(0);
  max_hash := uint64(0);

  if len(s.Events) == 0 {
    return uint64(0)
  }

  for ev,_ := range s.Events {
    hash := fast_hash(seed, ev);
    if(hash > max_hash){
      max_val = ev
      max_hash = hash
    }
  }

  return max_val
}

func (s* Emulator) GetHash(length uint) []byte{
  curr_order_salt := order_salt
  fmt.Printf("events: %v\n", s.Events);
  res := make([]byte, length);
  for i := uint(0) ; i < length ; i++ {
    res[i] = byte( fast_hash(final_salt, s.GetMaxEventByHash(curr_order_salt) ) );
    curr_order_salt = fast_hash(order_salt, curr_order_salt)
  }
  return res;
}
