#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <unicorn/unicorn.h>
#include <capstone/capstone.h>
#include "tpl/src/tpl.h"
#include "utils.h"

#define CODE "\xb8\x01\x00\x00\x00\x0f\xae\x24\x25\x00\x20\x40\x00\x90\x90\x90"

static void hook_code64(uc_engine *uc, void *user_data)
{
    uint64_t rip;
    csh handle;
    cs_insn *insn;
    uint8_t *code;
    size_t size = 15;

    printf(">>> RIP is 0x%" PRIx64 "\n", rip);
    uc_reg_read(uc, UC_X86_REG_RIP, &rip);
    code = calloc(1, 16);
    uc_mem_read(uc, rip, code, size);
    if(cs_open(CS_ARCH_X86, CS_MODE_64, &handle)){
        printf("[error] cs_open(%d, %d, 0x%08lx)\n", CS_ARCH_X86, CS_MODE_64, &handle);
        return;
    }

    insn = cs_malloc(handle);    
    if(cs_disasm_iter(handle, (const uint8_t **)&code, &size, &rip, insn)){
        printf("0x%08lx:\t%s\t%s\n", insn->address, insn->mnemonic, insn->op_str);  
    }else puts("[error] disassemble!");
    


    // Uncomment below code to stop the emulation using uc_emu_stop()
    // if (address == 0x1000009)
    //    uc_emu_stop(uc);
}

int main(){
    uc_err err;
    uc_engine *uc;

    err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
    if (err != UC_ERR_OK) {
        printf("Failed on uc_open() with error returned: %u\n", err);
        return -1;
    }
    uc_mem_map(uc, 0x401000, 0x2000, UC_PROT_ALL);
    uc_mem_write(uc, 0x401000, CODE, sizeof(CODE) - 1);

    uc_hook code_hook, err_mem_hook, code_inv_hook;
    if(1){
        err = uc_hook_add(uc, &code_hook, UC_HOOK_CODE, hook_code64, NULL, 1, 0);
        if (err) {
            printf("Failed on uc_hook_add() with error returned %u: %s\n",
            err, uc_strerror(err));
        }
    }
    err = uc_emu_start(uc, 0x401000, 0, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned %u: %s\n",
        err, uc_strerror(err));
    }

    return 1;
}