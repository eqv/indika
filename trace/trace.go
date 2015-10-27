package trace

import (
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
  "fmt"
)

type BlockRange struct {
  From,To uint64;
}

func min(a,b uint64) uint64{
  if(a<b) {return a} else {return b}
}
func max(a,b uint64) uint64{
  if(a>b) {return a} else {return b}
}

func (s* BlockRange) intersects(from,to uint64) bool{
  upper := min(s.To,to);
  lower := max(s.From,from);
  return lower <= upper;
}

func NewBlockRange(from,to uint64) BlockRange{
  return BlockRange{From: from, To: to}
}

type Trace struct{ 
  Events map[uint64]bool
  blocks_to_visit *map[BlockRange]bool
  WorkingSet *WorkingSet
}

func NewTrace(workingset_size int, blocks_to_visit *map[BlockRange]bool) *Trace{
  t := new(Trace);
  t.Events = make(map[uint64]bool);
  t.WorkingSet = NewWorkingSet(workingset_size);
  t.blocks_to_visit = blocks_to_visit;
  return t
}

func (s *Trace) AddBlockRange(from, to uint64) {
  for rng,visited := range *s.blocks_to_visit {
    if !visited && rng.intersects(from,to) {
      (*s.blocks_to_visit)[rng] = false;
    }
  }
}

func(s *Trace) ReadEvent(addr uint64){
  s.Events[ReadEventHash(addr)] = true;
}

func(s *Trace) WriteEvent(addr,value uint64){
  s.Events[WriteEventHash(addr,value)] = true;
}

func(s *Trace) SyscallEvent(number uint64){
  s.Events[SysEventHash(number)] = true;
}


func (s* Trace) FirstFreeAddress() uint64 {
  for rng,visited := range *s.blocks_to_visit {
    if !visited {return rng.From}
  }
  return 0;
}

func (s* Trace) AddHooks(mu uc.Unicorn) {

	mu.HookAdd(uc.HOOK_BLOCK, func(mu uc.Unicorn, addr uint64, size uint32) {
    s.AddBlockRange(addr, addr+uint64(size));
	})

	mu.HookAdd(uc.HOOK_MEM_READ|uc.HOOK_MEM_WRITE, func(mu uc.Unicorn, access int, addr uint64, size int, value int64) {
		if access == uc.MEM_WRITE {
      s.WriteEvent(addr,uint64(value));
		} else {
      s.ReadEvent(addr);
		}
	})

	invalid := uc.HOOK_MEM_READ_INVALID | uc.HOOK_MEM_WRITE_INVALID | uc.HOOK_MEM_FETCH_INVALID
	mu.HookAdd(invalid, func(mu uc.Unicorn, access int, addr uint64, size int, value int64) bool {
    s.WorkingSet.Map(addr, uint64(size), mu)
		return true
	})

	mu.HookAdd(uc.HOOK_INSN, func(mu uc.Unicorn) {
		rax, _ := mu.RegRead(uc.X86_REG_RAX)
    s.SyscallEvent(rax)
	}, uc.X86_INS_SYSCALL)
}

func (s *Trace) GetMaxEventByHash(seed uint64) uint64{
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

func (s* Trace) GetHash(length uint) []byte{
  curr_order_salt := order_salt
  fmt.Printf("events: %v\n", s.Events);
  res := make([]byte, length);
  for i := uint(0) ; i < length ; i++ {
    res[i] = byte( fast_hash(final_salt, s.GetMaxEventByHash(curr_order_salt) ) );
    curr_order_salt = fast_hash(order_salt, curr_order_salt)
  }
  return res;
}
