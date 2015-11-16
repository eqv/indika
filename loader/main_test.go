package blanket_emulator

import (
//	"fmt"
  "testing"
//  "gopkg.in/vmihailenco/msgpack.v2"
  "github.com/ranmrdrakono/indika/loader/elf"
)

func TestRun(t *testing.T) {
  elf.Run("../samples/binutils/bin_O1/gdb")
}
