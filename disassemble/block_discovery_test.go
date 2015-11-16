package disassemble 

import ( 
        "github.com/bnagy/gapstone"
        "testing"
       )

var code = "\x55\x48\x89\xe5\x89\x7d\xec\x89\x75\xe8\x8b" +
	"\x45\xe8\x01\x45\xec\xd1\x65\xe8\x8b\x55\xec" +
	"\x8b\x45\xe8\x01\xd0\x3d\x38\x05\x00\x00\x75" +
	"\x14\xc7\x45\xfc\x00\x00\x00\x00\xc7\x45\xec" +
	"\x00\x00\x00\x00\x83\x45\xe8\x02\xeb\x20\xc7" +
	"\x45\xfc\x06\x00\x00\x00\x8b\x45\xe8\x01\x45" +
	"\xec\x8b\x55\xec\x8b\x45\xfc\x01\xd0\x85\xc0" +
	"\x75\x07\xb8\x00\x00\x00\x00\xeb\x05\xb8\x01" +
	"\x00\x00\x00\x5d\xc3"


func TestRun(t *testing.T) {
	/* init engine */
	engine, err := gapstone.New(gapstone.CS_ARCH_X86,
		gapstone.CS_MODE_64)

	/* detailed options. enables parsing jump arguments*/
	engine.SetOption(gapstone.CS_OPT_DETAIL, gapstone.CS_OPT_ON)

	if err == nil {

		defer engine.Close()

		/* disassemble code */
		instrs, err := engine.Disasm([]byte(code), 0x10000, 0)

		/* build basic blocks */
		if err == nil {
			blocks := Discover_basic_blocks(instrs)
			print_blocks(blocks)

			return
		}
	}
}
