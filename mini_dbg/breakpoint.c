#include "utils.h"

void brk_enable(Breakpoint *bp){
    unsigned long data = ptrace(PTRACE_PEEKDATA, bp->b_pid, bp->b_addr, 0);
    bp->b_saved_data = data & 0xff;     //save LSB
    data = ((data & ~0xff) | INT3);
    ptrace(PTRACE_POKEDATA, bp->b_pid, bp->b_addr, data);
    bp->b_enabled = 1;
}

void brk_disable(Breakpoint *bp){
    unsigned long data = ptrace(PTRACE_PEEKDATA, bp->b_pid, bp->b_addr, 0);
    data = ((data & ~0xff) | bp->b_saved_data);
    ptrace(PTRACE_POKEDATA, bp->b_pid, bp->b_addr, data);
    bp->b_enabled = 0;
}