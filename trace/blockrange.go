package trace

type BlockRange struct {
  From,To uint64;
}

func min(a,b uint64) uint64{
  if(a<b) {return a} else {return b}
}
func max(a,b uint64) uint64{
  if(a>b) {return a} else {return b}
}

func (s* BlockRange) intersects(from,to uint64) bool{
  upper := min(s.To,to);
  lower := max(s.From,from);
  return lower <= upper;
}

func NewBlockRange(from,to uint64) BlockRange{
  return BlockRange{From: from, To: to}
}
