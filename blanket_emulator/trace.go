package blanket_emulator

import (
	ds "github.com/ranmrdrakono/indika/data_structures"
)

type Trace struct {
	blocks_to_visit *map[uint64]ds.BB
  blocks_to_states map[uint64]*ds.State
}

func NewTrace(blocks_to_visit *map[uint64]ds.BB) *Trace {
	t := new(Trace)
	t.blocks_to_visit = blocks_to_visit
  t.blocks_to_states = make(map[uint64]*ds.State)
  for addr,_ := range *blocks_to_visit {
    t.blocks_to_states[addr] = nil
  }
	return t
}

func (s *Trace) AddBlockRangeVisited(from, to uint64) {
	for addr,blck := range *s.blocks_to_visit {
		if blck.Rng.Intersects(from, to) {
			delete(*s.blocks_to_visit, addr)
			delete(s.blocks_to_states, addr)
		}
	}
}

func (s *Trace) FirstUnseenBlock() (uint64, bool) {
	min := ^uint64(0)
	valid := false
	for addr,_ := range *s.blocks_to_visit {
		if addr < min {
			min = addr
			valid = true
		}
	}
	return min, valid
}
