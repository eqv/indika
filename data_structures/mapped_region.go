package data_structures

type PageFlags uint

const (
	X PageFlags = 1
	R PageFlags = 2
	W PageFlags = 4
)

type MappedRegion struct {
	Data  []byte
	Flags PageFlags
	Range Range
}

func NewMappedRegion(data []byte,flags PageFlags, rng Range) *MappedRegion {
  return &MappedRegion{Data: data, Flags: flags, Range: rng}
}
