package trace

import (
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
)

const pagesize = 4096

type WorkingSet struct{ 
  mapped []uint64;
  newest int;
  oldest int;
}

func NewWorkingSet(size int) *WorkingSet{
  res := new(WorkingSet)
  res.mapped = make([]uint64, size)
  res.newest = -1
  res.oldest = -1
  return res
}


func (s *WorkingSet) Map(addr, size uint64, mu uc.Unicorn){
    alignment := (addr % pagesize)
    base_addr := addr - alignment
    mu.MemMap(base_addr, uint64(pagesize))
    mu.MemWrite(base_addr, GetMem(base_addr,pagesize))
    s.StoreInWorkingSet(base_addr, mu)
    if(addr + size > base_addr + pagesize) { //sometimes we might need to map 2 pages
      s.Map(base_addr + pagesize, 1, mu) //map next pages as well
    }
}

func (s *WorkingSet) StoreInWorkingSet(addr uint64, mu uc.Unicorn){
  if s.newest == -1 {
    s.mapped[0] = addr
    s.oldest = 0
    s.newest = 0
  }
  s.newest = (s.newest + 1) % len(s.mapped)
  if(s.newest  == s.oldest){ // unmap old page
    addr_to_unmap := s.mapped[s.oldest]
    mu.MemUnmap(addr_to_unmap,pagesize)
  }
  s.oldest = (s.oldest + 1) % len(s.mapped)
  s.mapped[s.newest] = addr
}
