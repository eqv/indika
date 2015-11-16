package blanket_emulator

import (
  ds "github.com/ranmrdrakono/indika/data_structures"
)

type Trace struct {
	blocks_to_visit *map[ds.Range]bool
}

func NewTrace(blocks_to_visit *map[ds.Range]bool) *Trace {
	t := new(Trace)
	t.blocks_to_visit = blocks_to_visit
	return t
}

func (s *Trace) AddBlockRange(from, to uint64) {
	for rng := range *s.blocks_to_visit {
		if rng.Intersects(from, to) {
			delete(*s.blocks_to_visit, rng)
		}
	}
}

func (s *Trace) FirstUnseenBlock() (uint64, bool) {
	min := ^uint64(0)
	valid := false
	for rng := range *s.blocks_to_visit {
		if rng.From < min {
			min = rng.From
			valid = true
		}
	}
	return min, valid
}
