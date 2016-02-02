package blanket_emulator

import (
	"github.com/go-errors/errors"
  "fmt"
)

const size_of_stackdump_above=128
const size_of_stackdump_below=128

type State struct {
  Regs map[int]uint64
  Stack []byte
  StackAddr uint64
}
func ExtractState(em *Emulator) (*State,*errors.Error) {
  s := &State{ Regs: make(map[int]uint64), Stack: nil, StackAddr: 0 }
  for _,reg := range em.Config.Arch.GetRegisters() {
    val, err := em.mu.RegRead(reg)
    if err != nil {
      return nil,wrap(err)
    }
    s.Regs[reg] = val
  }
  base,err := em.mu.RegRead(em.Config.Arch.GetRegStack())
  if err != nil {
    return nil,wrap(err)
  }
  begin := base-size_of_stackdump_above
	mem, err := em.ReadMemory(begin, size_of_stackdump_above+size_of_stackdump_below)
  if err != nil {
    return nil,wrap(err)
  }
  s.Stack = mem
  s.StackAddr = begin
  fmt.Printf("Extracted state: %#v", s)
  return s,nil
}

func (s *State) Apply(em *Emulator) *errors.Error{
  fmt.Printf("Applying state: %#v", s)
  for reg,val := range s.Regs {
    err := em.mu.RegWrite(reg,val)
    if err != nil {
      return wrap(err)
    }
  }
  if err := em.WriteMemory(s.StackAddr, s.Stack); err != nil {
    return err
  }
  return nil
}

