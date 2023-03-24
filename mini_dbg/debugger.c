#include "utils.h"
#include <capstone/capstone.h>
#include "tpl/src/tpl.h"

extern size_t n_regs;
extern struct reg_descriptor g_register_descriptors[];

static void continue_execution(Debugger *dbg);
static void exit_debugger(Debugger *dbg);
static void show_UI(Debugger *dbg);
static void snapshot(Debugger *dbg);

void dbg_run(Debugger *dbg){
    int wait_status;
    char *cmd;
    waitpid(dbg->d_pid, &wait_status, 0);
    /*UI for start up*/
    show_UI(dbg);
    while((cmd = linenoise("minidbg$ ")) != NULL){
        dbg_handle_command(dbg, cmd);
        linenoiseHistoryAdd(cmd);
        linenoiseFree(cmd);
    }
}

void dbg_handle_command(Debugger *dbg, char *cmd){
    char *lcmd = strdup(cmd);
    char *argv[8] = { 0 };    
    char *command;

    argv[0] = strtok(lcmd, " ");
    for(int i = 1; i < 8; i++){
        argv[i] = strtok(NULL, " ");
        if(argv[i] == NULL) break;
    }
    command = argv[0];
    if(command == NULL) return;
    if(is_prefix(command, "continue")){
        continue_execution(dbg);
    }else if(is_prefix(command, "quit")){
        exit_debugger(dbg);
    }else if(is_prefix(command, "break")){      /*format: break/b [addr]*/
        if(argv[1] == NULL)
            puts("command break expect an address!");
        else{
            dbg_set_breakpoint_at_address(dbg, strtoul(argv[1], NULL, 16));
        }
    }else if(is_prefix(command, "register")){   /*format: reg/r dump OR reg/r read/write [reg] value(hex)*/
        if(is_prefix(argv[1], "dump"))
            dbg_dump_all_regs(dbg);
        else if(is_prefix(argv[1], "read")){
            printf("value:\t0x%08lx\n", get_register_value(dbg->d_pid, get_register_from_name(argv[2])));
        }else if(is_prefix(argv[1], "write")){
            set_register_value(dbg->d_pid, get_register_from_name(argv[2]), strtoul(argv[3], NULL, 16));
        }
    }else if(is_prefix(command, "memory")){     /*memory/m read [addr] OR write [addr] [value]*/
        if(is_prefix(argv[1], "read")){
            printf("value:\t0x%08lx\n", dbg_read_memory(dbg, strtoul(argv[2], NULL, 16)));
        }
        else if(is_prefix(argv[1], "write")){
            printf("0x%08lx\t->\t", dbg_read_memory(dbg, strtoul(argv[2], NULL, 16)));
            dbg_write_memory(dbg, strtoul(argv[2], NULL, 16), strtoul(argv[3], NULL, 16));
            printf("0x%08lx\n", dbg_read_memory(dbg, strtoul(argv[3], NULL, 16)));
        }
    }else if(is_prefix(command, "step")){       /*step in OR step over*/
        if(is_prefix(argv[1], "in")){
            dbg_step_in(dbg);
        }else if(is_prefix(argv[1], "over")){
            dbg_step_over(dbg);
        }else{
            puts("Usage: step in / step over");
        }
    }else if(is_prefix(command, "snap")){
        snapshot(dbg);
    }
    else{
        fprintf(stderr, "Unkown command: %s.\n", command);
    }

    return free(lcmd);
}

void dbg_set_breakpoint_at_address(Debugger *dbg, unsigned long addr){
    Breakpoint *bp;

    printf("Set breakpoint at 0x%08lx\n", addr);
    HASH_FIND_PTR(dbg->d_brks, &addr, bp);
    if(bp == NULL){
        /*no breakpoint for addr insert one*/
        bp = (Breakpoint *)malloc(sizeof(Breakpoint));
        bp->b_addr = addr;
        bp->b_pid = dbg->d_pid;
        brk_enable(bp);
        /*bp initial done then add it to map*/
        HASH_ADD_PTR(dbg->d_brks, b_addr, bp);
    }else{
        puts("Breakpoint exist!");
    }
}

void dbg_dump_all_regs(Debugger *dbg){
    struct reg_descriptor rd;
    puts("-------------------------[Registers]-------------------------");
    for(int i = 0; i < n_regs; i++){
        rd = g_register_descriptors[i];
        printf("%s\t0x%08lx\n", rd.name, get_register_value(dbg->d_pid, rd.r));
    }
}

uint64_t dbg_read_memory(Debugger *dbg, uint64_t address){
    return ptrace(PTRACE_PEEKDATA, dbg->d_pid, address, NULL);
}

void dbg_write_memory(Debugger *dbg, uint64_t address, uint64_t value){
    ptrace(PTRACE_POKEDATA, dbg->d_pid, address, value);
}
/**
 * The caller need to make sure we are now in the middle of breaked instruction or this function do noting!
 * then here we try to step over it;
*/
void dbg_step_over_breakpoint(Debugger *dbg){
    uint64_t possible_pc_prev = get_pc(dbg) - 1;
    Breakpoint *bp = NULL;

    HASH_FIND_PTR(dbg->d_brks, &possible_pc_prev, bp);
    if(bp != NULL && bp->b_enabled){
        /*process just triggered a breakpoint, we need to set back pc*/
        brk_disable(bp);
        set_pc(dbg, possible_pc_prev);
        ptrace(PTRACE_SINGLESTEP, dbg->d_pid, NULL, NULL);
        wait_for_signal(dbg);
        brk_enable(bp);
    }
    
}
/**
 * This command invoked in two situation:
 * 1.Start of debuggering
 * 2.Continue from an breakpoint
*/
static void continue_execution(Debugger *dbg){
    int child_status;
    uint64_t possible_pc;
    Breakpoint *bp = NULL;

    puts("continue...");
    dbg_step_over_breakpoint(dbg);
    /*when let child continue debugger need to wait until child stop again or finished to get another command*/
    ptrace(PTRACE_CONT, dbg->d_pid, 0, 0);
    waitpid(dbg->d_pid, &child_status, 0);
    if(WIFEXITED(child_status)){
        puts("\e[31mDebuggee process done!\e[0m");
        return;
    }
    /*Maybe triggered a breakpoint so before we show UI we need to check it*/
    possible_pc = get_pc(dbg) - 1;
    HASH_FIND_PTR(dbg->d_brks, &possible_pc, bp);
    if(bp != NULL && bp->b_enabled){
        brk_disable(bp);
        set_pc(dbg, possible_pc);
        show_UI(dbg);
        set_pc(dbg, possible_pc + 1);
        brk_enable(bp);
        return;
    }else
        show_UI(dbg);
    
}

static void exit_debugger(Debugger *dbg){
    ptrace(PTRACE_KILL, dbg->d_pid, 0, 0);
    exit(0);
}

/**
 * This function invoked in situation:
 * 1.PTRACE_SINGLESTEP the current instruction which maybe inserted a breakpoint OR maybe not
 * 2.already triggered a breakpoint(0xcc) PTRACE_SINGLESTEP the broken instruction
 * we can show UI here
*/
void dbg_step_in(Debugger *dbg){
    static bool one_machine_code_flag = false;
    uint64_t possible_pc, data;
    Breakpoint *bp = NULL;
    csh handle = 0;
    cs_insn* insn;
    size_t count;
    int child_status;

    if(!one_machine_code_flag){
        possible_pc = get_pc(dbg) - 1;          /*if this is breakpoint int 3 executed*/
        HASH_FIND_PTR(dbg->d_brks, &possible_pc, bp);
        if(bp != NULL && bp->b_enabled){
            brk_disable(bp);
            /*check for single machine code instruction*/
            data = ptrace(PTRACE_PEEKDATA, dbg->d_pid, possible_pc, NULL);  
            if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle)) {
                printf("[error]: Failed to initialize capstone engine!\n");
                exit(-1);
            }
            cs_disasm(handle, (unsigned char*)&data, 8, 0x1000, 1, &insn);
            if(insn->size == 1){
                one_machine_code_flag = true;
            }else{
                one_machine_code_flag = false;
            }
            set_pc(dbg, possible_pc);
            ptrace(PTRACE_SINGLESTEP, dbg->d_pid, NULL, NULL);
            wait_for_signal(dbg);
            brk_enable(bp);
        }else{
            /*if we are here then this`s caused by PTRACE_SINGLESTEP and maybe we going to trigger a breakpoint or maybe not*/
            possible_pc += 1;
            one_machine_code_flag = false;
            HASH_FIND_PTR(dbg->d_brks, &possible_pc, bp);
            if(bp != NULL && bp->b_enabled){
                brk_disable(bp);
                ptrace(PTRACE_SINGLESTEP, dbg->d_pid, NULL, NULL);
                wait_for_signal(dbg);
                brk_enable(bp);
            }else{
                ptrace(PTRACE_SINGLESTEP, dbg->d_pid, NULL, NULL);
                wait_for_signal(dbg);
            }   
        }
    }else{
        /*the previous instruction is a single machine code instruction and breakpoint*/
        possible_pc = get_pc(dbg);      /*check current pc*/
        one_machine_code_flag = false;
        HASH_FIND_PTR(dbg->d_brks, &possible_pc, bp);
        if(bp != NULL && bp->b_enabled){
            brk_disable(bp);
            ptrace(PTRACE_SINGLESTEP, dbg->d_pid, NULL, NULL);
            wait_for_signal(dbg);
            brk_enable(bp);
        }else{
            ptrace(PTRACE_SINGLESTEP, dbg->d_pid, NULL, NULL);
            wait_for_signal(dbg);            
        }

    }
    show_UI(dbg);
}

/**
 * This function invoked in 4 situation:
 * 1.Just work as step in
 * 2.jump over a call but has triggered an breakpoint(0xcc)
 * 3.jump over a call but no breakpoint in current call instruction
 * 4.jump over a call but there is 0xcc in current call instruction
 * we can show UI here
*/
void dbg_step_over(Debugger *dbg){
    uint64_t possible_pc_prev = get_pc(dbg) - 1;        /*if this is breakpoint int 3 executed*/
    uint64_t possible_pc_currn = possible_pc_prev + 1;   /*if current instruction is breakpoint*/
    Breakpoint *bp_prev = NULL;
    Breakpoint *bp_currn = NULL;
    uint64_t data;
    uint64_t next_addr;

    /*Maybe stoped for triggered a breakpoint*/
    /*previous instruction. Jump over a call but has triggered an breakpoint(0xcc)*/
    HASH_FIND_PTR(dbg->d_brks, &possible_pc_prev, bp_prev);
    if(bp_prev != NULL && bp_prev->b_enabled && bp_prev->b_saved_data == 0xE8){     /*call`s op code is 0xE8*/
        /*call instruction has been triggered*/
        brk_disable(bp_prev);
        data = ptrace(PTRACE_PEEKDATA, dbg->d_pid, possible_pc_prev, NULL);
        csh handle = 0;
        cs_insn* insn;
        size_t count;
        int child_status;
        if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle)) {
            printf("[error]: Failed to initialize capstone engine!\n");
            exit(-1);
	    }
        cs_disasm(handle, (unsigned char*)&data, 8, possible_pc_prev, 1, &insn);
        next_addr = possible_pc_prev + insn->size;
        dbg_set_breakpoint_at_address(dbg, next_addr);
        set_pc(dbg, possible_pc_prev);
        continue_execution(dbg);                        /*Probably trigger another breakpoint in the function. So we need to disable it when stop*/
        brk_enable(bp_prev);
        
        HASH_FIND_PTR(dbg->d_brks, &next_addr, bp_prev);
        if(bp_prev != NULL && bp_prev->b_enabled){
            brk_disable(bp_prev);                       /*disable it*/
        }
        if((get_pc(dbg) - 1) == next_addr){             /*we stoped maybe because of triggering int3 below the call. So after continue we should check executed int3*/
            set_pc(dbg, next_addr);          
        }
        cs_free(insn, 1);
        cs_close(&handle);
        return;
    }else if(bp_prev != NULL && bp_prev->b_enabled && bp_prev->b_saved_data != 0xE8){
        /*normal instruction has been triggered. Just work as step in*/
        dbg_step_in(dbg);
        return;
    }

    /*stoped for PTRACE_SINGLESTEP*/
    /*current instruction. Jump over a call but there is 0xcc in current call instruction*/
    HASH_FIND_PTR(dbg->d_brks, &possible_pc_currn, bp_currn);
    if(bp_currn != NULL && bp_currn->b_enabled && bp_currn->b_saved_data == 0xE8){
        /*current instruction is breakpoint and it`s a function invoking*/
        brk_disable(bp_currn);
        data = ptrace(PTRACE_PEEKDATA, dbg->d_pid, possible_pc_currn, NULL);
        csh handle = 0;
        cs_insn* insn;
        size_t count;
        int child_status;
        if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle)) {
            printf("[error]: Failed to initialize capstone engine!\n");
            exit(-1);
	    }
        cs_disasm(handle, (unsigned char*)&data, 8, possible_pc_currn, 1, &insn);
        next_addr = possible_pc_currn + insn->size;
        dbg_set_breakpoint_at_address(dbg, next_addr);
        continue_execution(dbg);                        /*Probably trigger another breakpoint in the function. So we need to disable it when stop*/
        brk_enable(bp_currn);
        HASH_FIND_PTR(dbg->d_brks, &next_addr, bp_currn);
        if(bp_currn != NULL && bp_currn->b_enabled){
            brk_disable(bp_currn);                      /*disable it*/
        }
        if((get_pc(dbg) - 1) == next_addr){             /*we stoped maybe because of triggering int3 below the call. So after continue we should check executed int3*/
            set_pc(dbg, next_addr);          
        }
        cs_free(insn, 1);
        cs_close(&handle);
        return;
    }else if(bp_currn != NULL && bp_currn->b_enabled && bp_currn->b_saved_data != 0xE8){
        /*current instruction is a breakpoint but not a calling so we could just step over. Just work as step in */
        dbg_step_in(dbg);
        return;
    }

    
    /*not breakpoint in current invoking OR current normal instruction*/
    data = ptrace(PTRACE_PEEKDATA, dbg->d_pid, possible_pc_currn, NULL);
    if((data & 0xff) == 0xE8){          
        /*Current instruction is a call.Set breakpoint at next instruction then continue*/
        csh handle = 0;
        cs_insn* insn;
        size_t count;
        int child_status;
        if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle)) {
            printf("[error]: Failed to initialize capstone engine!\n");
            exit(-1);
	    }
        cs_disasm(handle, (unsigned char*)&data, 8, possible_pc_currn, 1, &insn);
        next_addr = possible_pc_currn + insn->size;
        dbg_set_breakpoint_at_address(dbg, next_addr);
        continue_execution(dbg);
        HASH_FIND_PTR(dbg->d_brks, &next_addr, bp_currn);
        if(bp_currn != NULL && bp_currn->b_enabled){
            brk_disable(bp_currn);
        }
        if((get_pc(dbg) - 1) == next_addr){             /*we stoped maybe because of triggering int3 below the call. So after continue we should check executed int3*/
            set_pc(dbg, next_addr);          
        }
        cs_free(insn, 1);
        cs_close(&handle);
        return;
    }else
        dbg_step_in(dbg);           /*Current instruction is normal. Just work as step in*/
}

void wait_for_signal(Debugger *dbg){
    int wait_status;
    waitpid(dbg->d_pid, &wait_status, 0);
}
/**
 * There are several situation we need to show UI(including registers and assembly)
 * 1.after step in, step over
 * 2.continue execution then triggered a breakpoint
 * The caller need to make sure current pc is the start point of next instruction which gonna be executed
*/
static void show_UI(Debugger *dbg){
    dbg_dump_all_regs(dbg);
    show_asm(dbg);
}

const char *Psnap = "snap.bin";
#define     NAMELEN     128

static uint8_t getPerm(char *sperm){
    uint8_t ret = 0;
    if(sperm[3] == 'p') ret |= 0b1000;
    if(sperm[2] == 'x') ret |= 0b001;
    if(sperm[1] == 'w') ret |= 0b010;
    if(sperm[0] == 'r') ret |= 0b100;
    return ret;
}

/**
 * There are several things we need to save, but let`s try to save regs and mems first
 * 1:Regs{name:value}
 * 2:Mems{addr, size, perm, name, data}
 * 
 * tpl_map("S($(iU)U)#A(S(UUcc#))A(B)", n_regs, 64)
*/
static void snapshot(Debugger *dbg){
    struct reg_descriptor rd;
    struct reg_map reg_maps[n_regs];        //"S($(iU)U)#", n_regs
    tpl_node *snapshotND;
    struct mem_map *mapHeader = NULL, *mem_list, mem_tmp;           //"A(S(UUcs))"
    tpl_bin tb;                             //"A(B)"

    snapshotND = tpl_map("S($(is)U)#A(S(UUus))A(B)", reg_maps, n_regs, &mem_tmp, &tb);
    /*save register*/
    for(int i = 0; i < n_regs; i++){
        rd = g_register_descriptors[i];
        reg_maps[i].reg_des = rd;
        reg_maps[i].value = get_register_value(dbg->d_pid, rd.r);
    }
    
    tpl_pack(snapshotND, 0);

    /** save maps we need to start from /proc/pid/maps file like this:
     * $ cat /proc/64361/maps 
        5589d9761000-5589d9825000 r-xp 00000000 08:01 805196                     /bin/zsh
        5589d9a24000-5589d9a26000 r--p 000c3000 08:01 805196                     /bin/zsh
        5589d9a26000-5589d9a2c000 rw-p 000c5000 08:01 805196                     /bin/zsh
        5589d9a2c000-5589d9a40000 rw-p 00000000 00:00 0 
        5589da2a7000-5589da634000 rw-p 00000000 00:00 0                          [heap]
        7f645d435000-7f645d445000 r-xp 00000000 08:01 411068                     /usr/lib/x86_64-linux-gnu/zsh/5.4.2/zsh/compctl.so
        7f645d445000-7f645d645000 ---p 00010000 08:01 411068                     /usr/lib/x86_64-linux-gnu/zsh/5.4.2/zsh/compctl.so
        7f645d645000-7f645d646000 r--p 00010000 08:01 411068                     /usr/lib/x86_64-linux-gnu/zsh/5.4.2/zsh/compctl.so
    */
   /*save map_info*/
    char path2maps[64];
    sprintf(path2maps, "/proc/%d/maps", dbg->d_pid);
    FILE *maps_fd = fopen(path2maps, "r");
    uint64_t A_start, A_end;
    char perm[64], name[NAMELEN];
    int mapSum = 0;
    /*use map list to recode all maps of target process*/
    while(fscanf(maps_fd, "%lx-%lx %[rwxp-] %*[0-9a-f] %*d:%*d %*d%[^\n]", &A_start, &A_end, perm, name) != EOF){
            for(int i = 0; i < NAMELEN;i++){         //strip blanks
                if(name[i] == ' ') name[i] = '\x00';
                else {
                    strcpy(name, &name[i]);
                    break; 
                }
            }
            struct mem_map *amap = (struct mem_map *)malloc(sizeof(struct mem_map));
            amap->addr = A_start;
            amap->size = (A_end - A_start);
            amap->perm = getPerm(perm);
            amap->name = malloc(NAMELEN);
            strcpy(amap->name, name);
            amap->next = mapHeader;
            mapHeader = amap;
            mapSum++;
    }
    fclose(maps_fd);
    for(mem_list = mapHeader; mem_list != NULL; mem_list = mem_list->next){
        mem_tmp = *mem_list;
        tpl_pack(snapshotND, 1);
    }

    /*save mems data*/
    void *data;       
    
    sprintf(path2maps, "/proc/%d/mem", dbg->d_pid);
    maps_fd = fopen(path2maps, "r");
    for(struct mem_map *map = mapHeader; map != NULL; map = map->next){         //"A(B)"
        data = malloc(map->size);       //better free this chunck each time
        fseek(maps_fd, map->addr, SEEK_SET);
        fread(data, 1024, (map->size / 1024), maps_fd);
        tb.sz = map->size;
        tb.addr = data;
        tpl_pack(snapshotND, 2);
        free(data);
    }
    fclose(maps_fd);
    tpl_dump(snapshotND, TPL_FILE, Psnap);
    tpl_free(snapshotND);

}