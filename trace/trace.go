package trace

type Trace struct{ 
  Events map[uint64]bool
  blocks_to_visit *map[BlockRange]bool
  WorkingSet *WorkingSet
}

func NewTrace(workingset_size int, blocks_to_visit *map[BlockRange]bool) *Trace{
  t := new(Trace);
  t.WorkingSet = NewWorkingSet(workingset_size);
  t.blocks_to_visit = blocks_to_visit;
  return t
}

func (s *Trace) AddBlockRange(from, to uint64) {
  for rng,visited := range *s.blocks_to_visit {
    if !visited && rng.intersects(from,to) {
      (*s.blocks_to_visit)[rng] = false;
    }
  }
}

func(s *Trace) ReadEvent(addr uint64){
  s.Events[ReadEventHash(addr)] = true;
}

func(s *Trace) WriteEvent(addr,value uint64){
  s.Events[WriteEventHash(addr,value)] = true;
}

func(s *Trace) SyscallEvent(number uint64){
  s.Events[SysEventHash(number)] = true;
}


func (s* Trace) FirstUnseenBlock() (uint64,bool){
  for rng,visited := range *s.blocks_to_visit {
    if !visited {return rng.From, true}
  }
  return 0, false;
}
