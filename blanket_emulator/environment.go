package blanket_emulator

import (
)

type Environment interface {
  GetReg(num int) uint64
  GetMem(addr, length uint64) []byte
}

type RandEnv struct {
  seed uint64
}


func NewRandEnv(seed uint64) *RandEnv{
  return &RandEnv{seed: seed}
}

func (s *RandEnv) GetReg(num int) uint64{
  return GetReg(num, s.seed)
}

func (s *RandEnv) GetMem(addr uint64, size uint64)[]byte {
  return GetMem(addr, size, s.seed)
}


type ConstEnv struct{ 
  val uint64
}

func NewConstEnv(val uint64) *ConstEnv{
  return &ConstEnv{val: val}
}

func (s *ConstEnv) GetReg(num int) uint64{
  return s.val
}

func (s *ConstEnv) GetMem(addr uint64, size uint64)[]byte {
  res := make([]byte, size)
  for i := uint64(0); i < size; i++ {
    res[i] = byte(s.val)
  }
  return res
}
