package blanket_emulator

import (
	"sort"
	"strings"
)

type EventSet map[Event]bool

func NewEventSet() *EventSet {
  res := make(map[Event]bool)
	return (*EventSet)(&res)
}
func (s *EventSet) Add(ev Event){
  (*s)[ev] = true
}

func (s *EventSet) GetMaxEventByHash(seed uint64) uint64 {
	max_val := uint64(0)
	max_hash := uint64(0)

	if len(*s) == 0 {
		return uint64(0)
	}

	for ev, _ := range *s {
		hash := fast_hash(seed, ev.Hash())
		if hash > max_hash {
			max_val = ev.Hash()
			max_hash = hash
		}
	}
	return max_val
}

func (s *EventSet) Inspect() string {
	res := make([]string, len(*s))
	i := 0
	for ev, _ := range *s {
		res[i] = ev.Inspect()
		i += 1
	}
	sort.Strings(res)
	return "[" + strings.Join(res, ", ") + "]"
}

func (s *EventSet) GetHash(length uint) []byte {
	curr_order_salt := order_salt
	res := make([]byte, length)
	for i := uint(0); i < length; i++ {
		res[i] = byte(fast_hash(final_salt, s.GetMaxEventByHash(curr_order_salt)))
		curr_order_salt = fast_hash(order_salt, curr_order_salt)
	}
	return res
}
