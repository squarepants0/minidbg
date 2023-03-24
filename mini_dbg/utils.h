#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>

#include "linenoise/linenoise.h"
#include "uthash/src/uthash.h"

#define     INT3    0xcc
#define     false   0
#define     true    1

typedef char bool;
typedef struct Debugger Debugger;
typedef struct Breakpoint Breakpoint;

/**
 * regs and memory
*/
enum reg{
    en_rax, en_rbx, en_rcx, en_rdx,
    en_rdi, en_rsi, en_rbp, en_rsp,
    en_r8,  en_r9,  en_r10, en_r11,
    en_r12, en_r13, en_r14, en_r15,
    en_rip, en_rflags,    en_cs,
    en_orig_rax, en_fs_base,
    en_gs_base,
    en_fs, en_gs, en_ss, en_ds, en_es
};

struct reg_descriptor {
    enum reg r;
    char *name;
};

struct reg_map {
    struct reg_descriptor reg_des;
    uint64_t value;
};
struct mem_map{
    uint64_t addr;
    uint64_t size;
    uint32_t perm;
    char *name;
    struct mem_map *next;
};


/**
 * debugger uitls
*/
typedef struct Debugger{
    const char *d_name;
    int d_pid;
    Breakpoint *d_brks;
}Debugger;

void dbg_run(Debugger *dbg);
void dbg_handle_command(Debugger *dbg, char *cmd);
void dbg_set_breakpoint_at_address(Debugger *dbg, unsigned long addr);
void dbg_dump_all_regs(Debugger *dbg);
uint64_t dbg_read_memory(Debugger *dbg, uint64_t address);
void dbg_write_memory(Debugger *dbg, uint64_t address, uint64_t value);
void dbg_step_in(Debugger *dbg);
void dbg_step_over(Debugger *dbg);
void wait_for_signal(Debugger *dbg);
/**
 * breakpoints utils
*/
typedef struct Breakpoint{
    int b_pid;
    unsigned long b_addr;           //map key
    int b_enabled;
    unsigned char b_saved_data;
    UT_hash_handle hh;
}Breakpoint;


void brk_enable(Breakpoint *bp);
void brk_disable(Breakpoint *bp);
int is_enabled(Breakpoint bp);
unsigned long get_address(Breakpoint bp);

/**
 * utils
*/
bool is_prefix(char *s, const char *ss);
uint64_t get_register_value(pid_t pid, enum reg r);
void set_register_value(pid_t pid, enum reg r, uint64_t value);
char *get_register_name(enum reg r);
enum reg get_register_from_name(char *name);
uint64_t get_pc(Debugger *dbg);
void set_pc(Debugger *dbg, uint64_t value);
void show_asm(Debugger *dbg);