package blanket_emulator

import (
	"github.com/go-errors/errors"
)

const size_of_stackdump_above=128
const size_of_stackdump_below=128

type State struct {
  Regs map[int]uint64
  Stack []byte
  StackAddr uint64
}

func NewState(em *Emulator) (*State, *errors.Error) {
  res := State{ Regs: make(map[int]uint64), Stack: nil, StackAddr: 0 }
  err := res.Extract(em)
  if err != nil {
    return nil, err
  }
  return &res, nil
}

func (s *State) Extract(em *Emulator) *errors.Error {
  for _,reg := range em.Config.Arch.GetRegisters() {
    val, err := em.mu.RegRead(reg)
    if err != nil {
      return wrap(err)
    }
    s.Regs[reg] = val
  }
  base,err := em.mu.RegRead(em.Config.Arch.GetRegStack())
  if err != nil {
    return wrap(err)
  }
  begin := base-size_of_stackdump_above
	mem, err := em.ReadMemory(begin, size_of_stackdump_above+size_of_stackdump_below)
  if err != nil {
    return wrap(err)
  }
  s.Stack = mem
  s.StackAddr = begin
  return nil
}

func (s *State) Apply(em *Emulator) *errors.Error{
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

