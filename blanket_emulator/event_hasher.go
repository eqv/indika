package blanket_emulator

type EventsToMinHash struct {
	Events map[uint64]bool
}

func NewEventsToMinHash() *EventsToMinHash {
	res := new(EventsToMinHash)
	res.Events = make(map[uint64]bool)
	return res
}

func (s *EventsToMinHash) WriteEvent(addr, value uint64) {
	s.Events[WriteEventHash(addr, value)] = true
}

func (s *EventsToMinHash) ReadEvent(addr uint64) {
	s.Events[ReadEventHash(addr)] = true
}

func (s *EventsToMinHash) BlockEvent(start_addr, end_addr uint64) {
}

func (s *EventsToMinHash) SyscallEvent(number uint64) {
	s.Events[SysEventHash(number)] = true
}

func (s *EventsToMinHash) InvalidInstructionEvent(offset uint64) {
	s.Events[InvalidInstructionEventHash(offset)] = true
}

func (s *EventsToMinHash) GetMaxEventByHash(seed uint64) uint64 {
	max_val := uint64(0)
	max_hash := uint64(0)

	if len(s.Events) == 0 {
		return uint64(0)
	}

	for ev, _ := range s.Events {
		hash := fast_hash(seed, ev)
		if hash > max_hash {
			max_val = ev
			max_hash = hash
		}
	}

	return max_val
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
