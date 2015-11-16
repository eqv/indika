package data_structures

type SymbolType uint;

const (
  FUNC SymbolType = 1
  DATA SymbolType = 2
  FILE SymbolType = 3
  THREADLOCAL SymbolType = 4
  SECTION SymbolType = 5
  UNKNOWN SymbolType = 6
)

type Symbol struct {
  Name string
  Type SymbolType
}

func NewSymbol(name string, symtype SymbolType) *Symbol{
  return &Symbol{Name: name, Type: symtype}
}
