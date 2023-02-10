#include "utils.h"
#include <capstone/capstone.h>
/**
 * consider of the longest instruction is 15bytes(x86_64) then we read 16bytes everytime
 * and disassemble it with capstone engine
 * befor invoking show_asm the caller should make sure current pc is not a breakpoint
*/
void show_asm(Debugger *dbg){
    csh handle;
    cs_insn *insn;
    size_t count;
    uint8_t *code;
    size_t size = 15;
    uint64_t address;

    if(cs_open(CS_ARCH_X86, CS_MODE_64, &handle)){
        printf("[error] cs_open(%d, %d, 0x%08lx)\n", CS_ARCH_X86, CS_MODE_64, &handle);
        exit(-1);
    }
    code = calloc(1, 16);
    address = get_pc(dbg);
    *(uint64_t *)code = ptrace(PTRACE_PEEKDATA, dbg->d_pid, address, NULL);
    *((uint64_t *)code + 1) = ptrace(PTRACE_PEEKDATA, dbg->d_pid, address + 8, NULL);
    
    /*before we show assembly after pc we should consider if there is breakpoint in machine code behind*/
    Breakpoint *bp = NULL;
    for(uint64_t i = 0, tmp = address; i < size; i++){
        HASH_FIND_PTR(dbg->d_brks, &tmp, bp);
        if(bp != NULL && bp->b_enabled){    
            *((uint8_t *)code + i) = bp->b_saved_data;
        }
        tmp++;
    }

    puts("-------------------------[Assembly]-------------------------");
    insn = cs_malloc(handle);
    while(cs_disasm_iter(handle, (const uint8_t **)&code, &size, &address, insn)){
        if(size + insn->size == 15)
            printf("\e[96m0x%08lx:\t%s\t%s\t<======RIP\e[0m\n", insn->address, insn->mnemonic, insn->op_str);
        else
            printf("0x%08lx:\t%s\t%s\n", insn->address, insn->mnemonic, insn->op_str);  
    }
    cs_free(insn, 1);
    cs_close(&handle);
}