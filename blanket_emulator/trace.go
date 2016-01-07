package blanket_emulator

import (
	ds "github.com/ranmrdrakono/indika/data_structures"
)

type Trace struct {
	blocks_to_visit map[uint64]*ds.BB
	end_addr_to_blocks map[uint64]*ds.BB
  blocks_to_states map[uint64]ds.State
}

func NewTrace(blocks_to_visit *map[uint64]ds.BB) *Trace {
	t := new(Trace)
	t.blocks_to_visit  = make(map[uint64]*ds.BB)
	t.end_addr_to_blocks  = make(map[uint64]*ds.BB)
  t.blocks_to_states = make(map[uint64]ds.State)
  for addr,_ := range *blocks_to_visit {
    bb  := (*blocks_to_visit)[addr] //avoid taking pointer to the temporary copy created by range
    t.blocks_to_visit[addr] = &bb
    t.end_addr_to_blocks[bb.Rng.To] = &bb
  }
	return t
}

func (s *Trace) AddBlockRangeVisited(from, to uint64) {
	for addr,blck := range s.blocks_to_visit {
		if blck.Rng.Intersects(from, to) {
			delete(s.blocks_to_visit, addr)
			delete(s.blocks_to_states, addr)
		}
	}
}

func (s *Trace) FirstUnseenBlock() (*ds.BB, ds.State) {
  var best_bb *ds.BB = nil
  var best_state ds.State = nil

	for _,bb := range s.blocks_to_visit {
    state,ok := s.blocks_to_states[bb.Rng.From]
    has_state := ok && state != nil
		if has_state && (best_bb == nil || bb.Rng.From < best_bb.Rng.From ) {
      best_bb = bb
      best_state = state
		}
	}
  if best_state != nil {
	  return best_bb, best_state
  }
	for _,bb := range s.blocks_to_visit {
		if best_bb == nil || bb.Rng.From < best_bb.Rng.From {
      best_bb = bb
		}
	}
  return best_bb, nil
}

func (s *Trace) DumpStateIfEndOfBB(em *Emulator, addr uint64, size uint32){
  if bb,ok := s.end_addr_to_blocks[addr+uint64(size)]; ok {
    state := em.DumpState()
    for _,addr := range bb.Transfers {
      if _,ok := s.blocks_to_states[addr] ; !ok{
        s.blocks_to_states[addr] = state
      }
    }
  }
}

func (s *Trace) NumberOfUnseenBlocks() int {
  return len(s.blocks_to_visit)
}
