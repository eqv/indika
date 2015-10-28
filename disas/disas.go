package main

import "github.com/bnagy/gapstone"
import "log"
import "fmt"


type BasicBlock struct{
    start uint64;
    end uint64;
}

var code =  "\x55\x48\x89\xe5\x89\x7d\xec\x89\x75\xe8\x8b" +
            "\x45\xe8\x01\x45\xec\xd1\x65\xe8\x8b\x55\xec" +
            "\x8b\x45\xe8\x01\xd0\x3d\x38\x05\x00\x00\x75" +
            "\x14\xc7\x45\xfc\x00\x00\x00\x00\xc7\x45\xec" +
            "\x00\x00\x00\x00\x83\x45\xe8\x02\xeb\x20\xc7" +
            "\x45\xfc\x06\x00\x00\x00\x8b\x45\xe8\x01\x45" +
            "\xec\x8b\x55\xec\x8b\x45\xfc\x01\xd0\x85\xc0" +
            "\x75\x07\xb8\x00\x00\x00\x00\xeb\x05\xb8\x01" +
            "\x00\x00\x00\x5d\xc3"


func main() {
    
    /* init engine */
    engine, err := gapstone.New(gapstone.CS_ARCH_X86, 
                                gapstone.CS_MODE_64)

    /* detailed options. enables parsing jump arguments*/
    engine.SetOption(gapstone.CS_OPT_DETAIL, gapstone.CS_OPT_ON)

    /* set of jmp/call instructions */
    var jmp_flags = make(map[uint]bool);	
    jmp_flags[gapstone.X86_INS_JL] = true;
    jmp_flags[gapstone.X86_INS_JLE] = true;
    jmp_flags[gapstone.X86_INS_JA] = true;
    jmp_flags[gapstone.X86_INS_JAE] = true;
    jmp_flags[gapstone.X86_INS_JB] = true;
    jmp_flags[gapstone.X86_INS_JBE] = true;
    jmp_flags[gapstone.X86_INS_JCXZ] = true;
    jmp_flags[gapstone.X86_INS_JECXZ] = true;
    jmp_flags[gapstone.X86_INS_JO] = true;
    jmp_flags[gapstone.X86_INS_JNO] = true;	
    jmp_flags[gapstone.X86_INS_JS] = true;
    jmp_flags[gapstone.X86_INS_JNS] = true;
    jmp_flags[gapstone.X86_INS_JP] = true;
    jmp_flags[gapstone.X86_INS_JNP] = true;	
    jmp_flags[gapstone.X86_INS_JE] = true;
    jmp_flags[gapstone.X86_INS_JNE] = true;
    jmp_flags[gapstone.X86_INS_JG] = true;
    jmp_flags[gapstone.X86_INS_JGE] = true;
    jmp_flags[gapstone.X86_INS_CALL] = true;
    jmp_flags[gapstone.X86_INS_LCALL] = true;
    jmp_flags[gapstone.X86_INS_JMP] = true;	
    jmp_flags[gapstone.X86_INS_LJMP] = true;


    /* set of basic blocks */
    blocks := make(map[BasicBlock]bool)

    /* set of start addresses of basic blocks */
    var bb_starts = make(map[uint64]bool);

    if err == nil {

        defer engine.Close()

        /* disassemble code */
        instrs, err := engine.Disasm([] byte (code), 0x10000, 0)


        /* build basic blocks */
        if err == nil {

            /* search start addresses*/
            
            /* first instruction in code sequene => basic block */
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
                    
                    /* instruction after a jump => basic block*/
                    bb_starts[uint64(instr.Address + instr.Size)] = true
                    }
            }
            
            /* search end addresses */
            var cur_bb uint64 = 0
            var instr_counter int = 0
            var next_addr uint64
            
            for _, instr := range instrs {
                /* instruction is first instruction of a basic block*/
                if _, ok := bb_starts[uint64(instr.Address)]; ok {
                    cur_bb = uint64(instr.Address)
                }
                
                /* increment instruction counter */
                instr_counter += 1
                
                /* address of next instruction */
                next_addr = uint64(instr.Address + instr.Size)
                
                /* next instruction == basic block start? */
                _, ok := bb_starts[next_addr]

                /* basic block start or last instruction in list */
                if (instr_counter == len(instrs)) || ok {
                    /* create and store basic block */
                    var bb BasicBlock
                    bb.start = cur_bb
                    bb.end = uint64(instr.Address)
                    blocks[bb] = true
                }
            }

            /* print basic blocks */
            for block, value := range blocks {
                if value {
                    fmt.Printf("(0x%x, 0x%x)\n", block.start, block.end)
                }
            }

            return
        }
        log.Fatalf("Disassembly error: %v", err)
    }
    log.Fatalf("Failed to initialize engine: %v", err)
}
