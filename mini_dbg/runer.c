#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <unicorn/unicorn.h>
#include <capstone/capstone.h>
#include "tpl/src/tpl.h"
#include "utils.h"

void code_hooker(uc_engine* uc, uint64_t address, uint32_t size,void *user_data){
    unsigned long rip = -1;
    csh handle;
    cs_insn *insn;
    uint8_t *code;
    size_t s = size;
    uint64_t ad = address;
    uc_err err;

    code = calloc(1, 0x10);
    err = uc_mem_read(uc, address, code, size);
    if(err != UC_ERR_OK) {
        uc_strerror(err);
        return;
    }
    if(cs_open(CS_ARCH_X86, CS_MODE_64, &handle)){
        printf("[error] cs_open(%d, %d, 0x%08lx)\n", CS_ARCH_X86, CS_MODE_64, &handle);
        return;
    }

    insn = cs_malloc(handle);    
    if(cs_disasm_iter(handle, (const uint8_t **)&code, &s, &ad, insn)){
        printf("0x%08lx:\t%s\t%s\n", insn->address, insn->mnemonic, insn->op_str);  
    }else puts("[error] disassemble!");
    cs_free(insn, 1);
    cs_close(&handle);

    // uc_reg_read(uc, UC_X86_REG_RIP, &rip);

    // printf("[PC] 0x%08lx\n", rip);
}

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

void err_mem_hooker(uc_engine *uc, void *user_data){
    uc_mem_region *region;
    uint32_t count;
    uc_err err;
    if ((err = uc_mem_regions(uc, &region, &count))) {
        uc_strerror(err);
    }
    for(int i = 0; i < count; i++){
        printf("start: 0x%08lx\tend: 0x%08lx\tperm: %s\n", region[i].begin, region[i].end, Nums2perm(region[i].perms));
    }
    uc_free(region);
    unsigned long rsp = -1;
    uint64_t value;
    
    uc_reg_read(uc, UC_X86_REG_RSP, &rsp);
    uc_mem_read(uc, rsp, &value, sizeof(value));
    printf("[SP] 0x%08lx\tvalue: 0x%08lx\n", rsp, value);
    uc_reg_read(uc, UC_X86_REG_RSI, &rsp);
    uc_mem_read(uc, 0x405078, &value, sizeof(value));
    printf("[RSI] 0x%08lx\tvalue: 0x%08lx\n", rsp, value);
    uc_mem_read(uc, 0x004010f0, &value, sizeof(value));
    printf("value: 0x%08lx\n", value);
    
}

void set_context(uc_engine *uc, struct reg_map reg_maps[]){
    //initialize register
    uc_reg_write(uc, UC_X86_REG_R15, &reg_maps[0].value);
    uc_reg_write(uc, UC_X86_REG_R14, &reg_maps[1].value);
    uc_reg_write(uc, UC_X86_REG_R13, &reg_maps[2].value);
    uc_reg_write(uc, UC_X86_REG_R12, &reg_maps[3].value);
    uc_reg_write(uc, UC_X86_REG_RBP, &reg_maps[4].value);
    uc_reg_write(uc, UC_X86_REG_RBX, &reg_maps[5].value);
    uc_reg_write(uc, UC_X86_REG_R11, &reg_maps[6].value);
    uc_reg_write(uc, UC_X86_REG_R10, &reg_maps[7].value);
    uc_reg_write(uc, UC_X86_REG_R9, &reg_maps[8].value);
    uc_reg_write(uc, UC_X86_REG_R8, &reg_maps[9].value);
    uc_reg_write(uc, UC_X86_REG_RAX, &reg_maps[10].value);
    uc_reg_write(uc, UC_X86_REG_RCX, &reg_maps[11].value);
    uc_reg_write(uc, UC_X86_REG_RDX, &reg_maps[12].value);
    uc_reg_write(uc, UC_X86_REG_RSI, &reg_maps[13].value);
    uc_reg_write(uc, UC_X86_REG_RDI, &reg_maps[14].value);
    // uc_reg_write(uc, UC_X86_REG_RIP, &reg_maps[16].value);
    uc_reg_write(uc, UC_X86_REG_CS, &reg_maps[17].value);
    uc_reg_write(uc, UC_X86_REG_RFLAGS, &reg_maps[18].value);
    uc_reg_write(uc, UC_X86_REG_RSP, &reg_maps[19].value);
    uc_reg_write(uc, UC_X86_REG_SS, &reg_maps[20].value);
    uc_reg_write(uc, UC_X86_REG_FS_BASE, &reg_maps[21].value);
    uc_reg_write(uc, UC_X86_REG_GS_BASE, &reg_maps[22].value);
    uc_reg_write(uc, UC_X86_REG_DS, &reg_maps[23].value);
    uc_reg_write(uc, UC_X86_REG_ES, &reg_maps[24].value);
    uc_reg_write(uc, UC_X86_REG_FS, &reg_maps[25].value);
    uc_reg_write(uc, UC_X86_REG_GS, &reg_maps[26].value);
}

int main(int argc, char *argv[]){
    uc_err err;
    uc_engine *uc;
    struct reg_map reg_maps[27];        //"S($(iU)U)#", n_regs
    struct mem_map *mapHeader = NULL, *mem_list, mem_tmp;           //"A(S(UUcs))"
    tpl_node *snapshotND;
    tpl_bin tb;                             //"A(B)"
    int oc, debugFlag = 0;
    
    while((oc = getopt(argc, argv, "dh")) != -1){
        switch (oc)
        {
        case 'd':
            debugFlag = 1;
            break;
        case 'h':
        default:
            puts("Usage: -d show debugInfo\n");
            exit(0);
        }
    }


    snapshotND = tpl_map("S($(is)U)#A(S(UUus))A(B)", reg_maps, 27, &mem_tmp, &tb);
    tpl_load(snapshotND, TPL_FILE, "snap.bin");
    tpl_unpack(snapshotND, 0);
    //initialize emulator in x86_64 mode
    err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
    if (err != UC_ERR_OK) {
        printf("Failed on uc_open() with error returned: %u\n", err);
        return -1;
    }
    set_context(uc, reg_maps);
    

    while(tpl_unpack(snapshotND, 1) > 0){
        // if(strlen(mem_tmp.name) == 0) printf("name: null\t");
        // else printf("name: %s\t", mem_tmp.name);
        // printf("address: 0x%08lx\tsize: 0x%08lx\tperm: %d\n", mem_tmp.addr, mem_tmp.size, mem_tmp.perm);
        // uc_mem_map(uc, mem_tmp.addr, mem_tmp.size, mem_tmp.perm & 0b0111);
        uc_mem_map(uc, mem_tmp.addr, mem_tmp.size, UC_PROT_ALL);
        tpl_unpack(snapshotND, 2);
        uc_mem_write(uc, mem_tmp.addr, tb.addr, tb.sz);
    }
    uc_hook code_hook, err_mem_hook, code_inv_hook;
    if(debugFlag){
        err = uc_hook_add(uc, &code_hook, UC_HOOK_CODE, code_hooker, NULL, 1, 0);
        err = uc_hook_add(uc, &code_inv_hook, UC_HOOK_INSN_INVALID, hook_code64, NULL, 1, 0);
        err = uc_hook_add(uc, &err_mem_hook, UC_HOOK_MEM_INVALID, err_mem_hooker, NULL, 1, 0);
        if (err) {
            printf("Failed on uc_hook_add() with error returned %u: %s\n",
            err, uc_strerror(err));
        }
    }

    err = uc_emu_start(uc, reg_maps[16].value, -1, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned %u: %s\n",
        err, uc_strerror(err));
    }

}