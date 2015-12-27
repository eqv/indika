package blanket_emulator
import ( 
  "sort"
  "strings"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
	log "github.com/Sirupsen/logrus"
  )

type EventsToMinHash struct {
	Events map[Event]bool
}

func NewEventsToMinHash() *EventsToMinHash {
	res := new(EventsToMinHash)
	res.Events = make(map[Event]bool)
	return res
}

func (s *EventsToMinHash) WriteEvent(em *Emulator, addr, value uint64){
  rsp,err := em.mu.RegRead(uc.X86_REG_RSP)
  check(wrap(err))
  if addr > GetReg(REG_STACK) && addr < rsp {
    log.WithFields(log.Fields{"addr": addr, "value": value}).Debug("Write to StackFrame")
  } else {
    s.Events[WriteEvent{Addr: addr, Value: value}] = true
    
  }
}

func (s *EventsToMinHash) ReadEvent(em *Emulator, addr uint64) {
	s.Events[ReadEvent(addr)] = true
}

func (s *EventsToMinHash) BlockEvent(em *Emulator, start_addr, end_addr uint64) {
}

func (s *EventsToMinHash) SyscallEvent(em *Emulator, number uint64) {
	s.Events[SyscallEvent(number)] = true
}

func (s *EventsToMinHash) InvalidInstructionEvent(em *Emulator, offset uint64) {
	s.Events[InvalidInstructionEvent(offset)] = true
}

func (s *EventsToMinHash) GetMaxEventByHash(seed uint64) uint64 {
	max_val := uint64(0)
	max_hash := uint64(0)

	if len(s.Events) == 0 {
		return uint64(0)
	}

	for ev, _ := range s.Events {
		hash := fast_hash(seed, ev.Hash())
		if hash > max_hash {
			max_val = ev.Hash()
			max_hash = hash
		}
	}

	return max_val
}

func (s *EventsToMinHash) Inspect() string{
  res := make([]string, len(s.Events))
   i := 0
  for ev,_ := range s.Events {
    res[i] = ev.Inspect()
    i+=1
  }
  sort.Strings(res)
  return "["+strings.Join(res,", ")+"]"
}

func (s *EventsToMinHash) GetHash(length uint) []byte {
	curr_order_salt := order_salt
	res := make([]byte, length)
	for i := uint(0); i < length; i++ {
		res[i] = byte(fast_hash(final_salt, s.GetMaxEventByHash(curr_order_salt)))
		curr_order_salt = fast_hash(order_salt, curr_order_salt)
	}
	return res
}
