package disassemble

import (
//	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/bnagy/gapstone"
	ds "github.com/ranmrdrakono/indika/data_structures"
  "fmt"
)

/* jump instructions */
var jmp_flags = make(map[uint]bool)
var jmp_no_return_flags = make(map[uint]bool)

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
	jmp_flags[gapstone.X86_INS_RET] = true
  jmp_no_return_flags[gapstone.X86_INS_RET] = true
	jmp_no_return_flags[gapstone.X86_INS_JMP] = true
	jmp_no_return_flags[gapstone.X86_INS_LJMP] = true
}


func makebb(ins gapstone.Instruction) *ds.BB{
  from := uint64(ins.Address)
  to := uint64(ins.Address)+uint64(ins.Size)
  return ds.NewBB(from, to, make([]uint64,0))
}

func get_transfer_targets( ins gapstone.Instruction) []uint64 {
      res := make([]uint64,0)
			for _, op := range ins.X86.Operands {
				if op.Type == gapstone.X86_OP_IMM {
          res = append(res, uint64(op.Imm))
				}
			}
      if _,ok := jmp_no_return_flags[ins.Id]; !ok {
			/* instruction succeeding a jump => new basic block*/
        res = append(res,uint64(ins.Address)+uint64(ins.Size))
      }
      return res
}

func search_basicblocks(ins []gapstone.Instruction) map[uint64]ds.BB{
  res := make(map[uint64]ds.BB)
  var curr_bb *ds.BB = nil

  for _, curr_instr := range ins {
    if curr_bb == nil {
      curr_bb = makebb(curr_instr)
    }
    //this is a jump instruction => add current bb
    if _,ok := jmp_flags[curr_instr.Id]; ok {
      curr_bb.Transfers = get_transfer_targets(curr_instr)
      curr_bb.Rng.To = uint64(curr_instr.Address+curr_instr.Size)
      res[curr_bb.Rng.From] = *curr_bb
      curr_bb = nil
    }
  }

  //finish last basic block
  if curr_bb != nil {
    last_instr := ins[len(ins)-1]
    curr_bb.Rng.To = uint64(last_instr.Address + last_instr.Size)
    res[curr_bb.Rng.From] = *curr_bb
  }
  return res
}

func GetBBs(codeoffset uint64, code []byte, function_bounds ds.Range) map[uint64]ds.BB {
	if function_bounds.To-function_bounds.From < 1 {
		return make(map[uint64]ds.BB)
	}

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

	return search_basicblocks(instrs)
}

func InspectMemory(addr uint64, code[]byte) string {
  engine, err := gapstone.New(gapstone.CS_ARCH_X86, gapstone.CS_MODE_64)
  if err != nil {
    return "DA Fail: "+err.Error()
  }
	instrs, err := engine.Disasm(code, addr, 0)
  if err != nil {
    return "DA Fail: "+err.Error()
  }
  ins := instrs[0]
  return fmt.Sprintf("%s %s",ins.Mnemonic, ins.OpStr)
}
