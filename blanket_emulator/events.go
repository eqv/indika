package blanket_emulator
import (
  "fmt"
)

type Event interface  {
  Hash() uint64
  Inspect() string
}

type ReadEvent uint64
type WriteEvent struct {
  Addr uint64
  Value uint64
}
type SyscallEvent uint64
type InvalidInstructionEvent uint64

func (addr ReadEvent) Hash() uint64 {
  return ReadEventHash(uint64(addr))
}

func (s WriteEvent) Hash() uint64 {
  return WriteEventHash(s.Addr,s.Value)
}

func (s SyscallEvent) Hash() uint64 {
  return SysEventHash(uint64(s))
}

func (s InvalidInstructionEvent) Hash() uint64 {
  return InvalidInstructionEventHash(uint64(s))
}

func (addr ReadEvent) Inspect() string {
  return fmt.Sprintf("Read([%x])", addr)
}

func (s WriteEvent) Inspect() string {
  return fmt.Sprintf("Write([%x]=%x)", s.Addr, s.Value)
}

func (s SyscallEvent) Inspect() string {
  return fmt.Sprintf("Sys(%x)", s)
}

func (s InvalidInstructionEvent) Inspect() string {
  return fmt.Sprintf("InvalidOpcode([%x])", s)
}
