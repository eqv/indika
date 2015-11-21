package disassemble

import (
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/bnagy/gapstone"
	ds "github.com/ranmrdrakono/indika/data_structures"
)

/* jump instructions */
var jmp_flags = make(map[uint]bool)

func init() {
	/* set of jmp/call instructions */
	jmp_flags[gapstone.X86_INS_JL] = true
	jmp_flags[gapstone.X86_INS_JLE] = true
	jmp_flags[gapstone.X86_INS_JA] = true
	jmp_flags[gapstone.X86_INS_JAE] = true
	jmp_flags[gapstone.X86_INS_JB] = true
	jmp_flags[gapstone.X86_INS_JBE] = true
	jmp_flags[gapstone.X86_INS_JCXZ] = true
	jmp_flags[gapstone.X86_INS_JECXZ] = true
	jmp_flags[gapstone.X86_INS_JO] = true
	jmp_flags[gapstone.X86_INS_JNO] = true
	jmp_flags[gapstone.X86_INS_JS] = true
	jmp_flags[gapstone.X86_INS_JNS] = true
	jmp_flags[gapstone.X86_INS_JP] = true
	jmp_flags[gapstone.X86_INS_JNP] = true
	jmp_flags[gapstone.X86_INS_JE] = true
	jmp_flags[gapstone.X86_INS_JNE] = true
	jmp_flags[gapstone.X86_INS_JG] = true
	jmp_flags[gapstone.X86_INS_JGE] = true
	jmp_flags[gapstone.X86_INS_CALL] = true
	jmp_flags[gapstone.X86_INS_LCALL] = true
	jmp_flags[gapstone.X86_INS_JMP] = true
	jmp_flags[gapstone.X86_INS_LJMP] = true
}

func Discover_basic_blocks(instrs []gapstone.Instruction) map[ds.Range]bool {
	/* set of basic blocks */
	var blocks = make(map[ds.Range]bool)

	/* discover addresses */
	bb_starts := search_start_addresses(instrs)
	bb_ends := search_end_addresses(instrs, bb_starts)

	/* create basic block */
	for start, end := range bb_ends {
		bb := ds.NewRange(start, end)
		blocks[bb] = true
	}

	return blocks
}

func search_start_addresses(instrs []gapstone.Instruction) map[uint64]bool {
	var bb_starts = make(map[uint64]bool)

	/* first instruction in code sequence => basic block */
	bb_starts[uint64(instrs[0].Address)] = true

	for _, instr := range instrs {
		/* jmp instruction */
		if _, ok := jmp_flags[instr.Id]; ok {

			/* jmp destination => basic block */
			for _, op := range instr.X86.Operands {
				if op.Type == gapstone.X86_OP_IMM {
					bb_starts[uint64(op.Imm)] = true
				}
			}

			/* instruction succeeding a jump => basic block*/
			bb_starts[uint64(instr.Address+instr.Size)] = true
		}
	}
	return bb_starts
}

func search_end_addresses(instrs []gapstone.Instruction, bb_starts map[uint64]bool) map[uint64]uint64 {
	var bb_ends = make(map[uint64]uint64)
	var cur_bb uint64 = 0
	var instr_counter int = 0
	var next_addr uint64

	for _, instr := range instrs {
		/* instruction is first instruction of a basic block*/
		if _, ok := bb_starts[uint64(instr.Address)]; ok {
			cur_bb = uint64(instr.Address)
		}

		instr_counter += 1
		next_addr = uint64(instr.Address + instr.Size)

		/* next instruction == basic block start? */
		_, ok := bb_starts[next_addr]

		/* basic block start or last instruction in list */
		if (instr_counter == len(instrs)) || ok {
			bb_ends[cur_bb] = uint64(instr.Address)
		}
	}
	return bb_ends
}

func print_blocks(blocks map[ds.Range]bool) {
	for block, value := range blocks {
		if value {
			fmt.Printf("(0x%x, 0x%x)\n", block.From, block.To)
		}
	}
}

func GetBasicBlocks(codeoffset uint64, code []byte, function_bounds ds.Range) map[ds.Range]bool {
	if function_bounds.To-function_bounds.From < 1 {
		return make(map[ds.Range]bool)
	}
	_ = "breakpoint"

	EP := function_bounds.From
	engine, err := gapstone.New(gapstone.CS_ARCH_X86, gapstone.CS_MODE_64)

	if err != nil {
		log.WithFields(log.Fields{"error": err}).Fatal("Failed to create Gapstone Disassembler")
	}
	if EP-codeoffset > uint64(len(code)) || EP < codeoffset || function_bounds.To > codeoffset+uint64(len(code)) {
		log.WithFields(log.Fields{"function range": function_bounds, "code offset": codeoffset, "len of code": len(code)}).Fatal("invalid offset in code")
	}

	offset_in_code := EP - codeoffset
	code = code[offset_in_code : offset_in_code+function_bounds.Length()]
	/* detailed options. enables parsing jump arguments*/
	engine.SetOption(gapstone.CS_OPT_DETAIL, gapstone.CS_OPT_ON)

	defer engine.Close()
	/* disassemble code */
	instrs, err := engine.Disasm(code, EP, 0)

	if err != nil {
		log.WithFields(log.Fields{"error": err}).Fatal("Failed to Disassemble")
	}

	return Discover_basic_blocks(instrs)
}
