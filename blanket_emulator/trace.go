package blanket_emulator

import ()

type Trace struct {
	Events          map[uint64]bool
	blocks_to_visit *map[BlockRange]bool
}

func NewTrace(blocks_to_visit *map[BlockRange]bool) *Trace {
	t := new(Trace)
	t.blocks_to_visit = blocks_to_visit
	return t
}

func (s *Trace) AddBlockRange(from, to uint64) {
	for rng := range *s.blocks_to_visit {
		if rng.intersects(from, to) {
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
