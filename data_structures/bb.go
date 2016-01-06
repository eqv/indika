package data_structures

type BB struct {
  Rng Range;
  Transfers []uint64;
}

func NewBB(from uint64 ,to uint64, transfers []uint64) *BB{
  rng := NewRange(from, to)
  return &BB{Rng: rng, Transfers: transfers}
}

