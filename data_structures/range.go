package data_structures

import (
	log "github.com/Sirupsen/logrus"
)

type Range struct {
	From, To uint64
}

func min(a, b uint64) uint64 {
	if a < b {
		return a
	} else {
		return b
	}
}
func max(a, b uint64) uint64 {
	if a > b {
		return a
	} else {
		return b
	}
}

func (s *Range) Include(addr uint64) bool {
	return s.From <= addr && addr <= s.To
}

func (s *Range) Intersects(from, to uint64) bool {
	upper := min(s.To, to)
	lower := max(s.From, from)
	return lower <= upper
}

func (s *Range) IntersectsRange(other Range) bool {
	upper := min(s.To, other.To)
	lower := max(s.From, other.From)
	return lower <= upper
}

func (s *Range) Length() uint64 {
	return s.To - s.From
}

func (s *Range) IsEmpty() bool {
	return s.To <= s.From
}

func NewRange(from, to uint64) Range {
	if from > to {
		log.WithFields(log.Fields{"from": from, "to": to}).Warning("Range with swaped bounds")
		tmp := to
		to = from
		from = tmp
	}
	return Range{From: from, To: to}
}
