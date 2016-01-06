package arch

type Arch interface {
  GetRegisters() []int
  IsRet(mem []byte) bool
  GetRegIP() int
  GetRegStack() int
  GetRegStackBase() int
  GetRegRet() int
  ToUnicornArchDescription() int //X86? ARM? PPC?
  ToUnicornModeDescription() int //32 or 64 byte
}
