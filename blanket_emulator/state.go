package blanket_emulator

import (
	"github.com/go-errors/errors"
	log "github.com/Sirupsen/logrus"
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
	mem, err2 := em.ReadMemory(begin, size_of_stackdump_above+size_of_stackdump_below)
  if err2 != nil {
    return nil,wrap(err)
  }
  s.Stack = mem
  s.StackAddr = begin
  return s,nil
}

func (s *State) Apply(em *Emulator) *errors.Error{
	log.WithFields(log.Fields{"state": s}).Info("Apply state")
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

