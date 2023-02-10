#include "utils.h"
#include <strings.h>
#include <string.h>
#include <sys/user.h>

/**
 * regs and memory
 * 
*/
const size_t n_regs = 27;
const struct reg_descriptor g_register_descriptors[] = {
    { en_r15, "r15" },
    { en_r14, "r14" },
    { en_r13, "r13" },
    { en_r12, "r12" },
    { en_rbp, "rbp" },
    { en_rbx, "rbx" },
    { en_r11, "r11" },
    { en_r10, "r10" },
    { en_r9, "r9" },
    { en_r8, "r8" },
    { en_rax, "rax" },
    { en_rcx, "rcx" },
    { en_rdx, "rdx" },
    { en_rsi, "rsi" },
    { en_rdi, "rdi" },
    { en_orig_rax, "orig_rax" },
    { en_rip, "rip" },
    { en_cs, "cs" },
    { en_rflags, "eflags" },
    { en_rsp, "rsp" },
    { en_ss, "ss" },
    { en_fs_base, "fs_base" },
    { en_gs_base, "gs_base" },
    { en_ds, "ds" },
    { en_es, "es" },
    { en_fs, "fs" },
    { en_gs, "gs" }
};

bool is_prefix(char *s, const char *ss){
    if(s == NULL || ss == NULL) return false;
    if(strlen(s) > strlen(ss)) return false;
    
    return !strncmp(s, ss, strlen(s));
}

uint64_t get_register_value(pid_t pid, enum reg r){
    struct user_regs_struct regs;
    int reg_descriptor_idx;
    uint64_t ret = 0;
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);

    /*locate reg_r`s index in user_regs_struct struct*/
    reg_descriptor_idx = -1;
    for(int i = 0; i < n_regs; i++){
        if(g_register_descriptors[i].r == r){
            reg_descriptor_idx = i;
            break;
        }
    }

    if(reg_descriptor_idx != -1){
        ret = *(uint64_t *)((uint64_t *)&regs + reg_descriptor_idx);
        return ret;
    }
    printf("[error] get_register_value(%d, %d)\n", pid, r);
    return ret;
}

void set_register_value(pid_t pid, enum reg r, uint64_t value){
    struct user_regs_struct regs;
    int reg_descriptor_idx;
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);

    /*locate reg_r`s index in user_regs_struct struct*/
    reg_descriptor_idx = -1;
    for(int i = 0; i < n_regs; i++){
        if(g_register_descriptors[i].r == r){
            reg_descriptor_idx = i;
            break;
        }
    }

    *(uint64_t *)((uint64_t *)&regs + reg_descriptor_idx) = value;
    ptrace(PTRACE_SETREGS, pid, NULL, &regs);

}

char *get_register_name(enum reg r){
    for(int i = 0; i < n_regs; i++){
        if(g_register_descriptors[i].r == r)
            return g_register_descriptors[i].name;
    }
    return NULL;
}

enum reg get_register_from_name(char *name){
    for(int i = 0; i < n_regs; i++){
        if(!strcasecmp(name, g_register_descriptors[i].name)){
            return g_register_descriptors[i].r;
        }
    }
    return -1;      /*-1 is impossible in reg_descriptor->r*/
}


uint64_t get_pc(Debugger *dbg){
    return get_register_value(dbg->d_pid, en_rip);
}

void set_pc(Debugger *dbg, uint64_t value){
    set_register_value(dbg->d_pid, en_rip, value);
}