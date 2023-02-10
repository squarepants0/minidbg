#include <sys/ptrace.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <wait.h>
#include <sys/user.h>
#include <stdlib.h>
#include <capstone/capstone.h>

void print_hex(unsigned char *data, int len){
    return;
}

csh handle;
uint64_t address;
cs_insn *insn;
cs_err err;
void print_asm(unsigned char *data, int len){
    
    
}

void load_executable_file(const char *filename, char *argv[]){
    printf("Tracee start run [%s]....\n", filename);
    char *envp[] = {"PATH=/bin", 0};

    ptrace(PTRACE_TRACEME, 0, 0, 0);
    
    execve(filename, argv, envp);    
}

void run_debugger(pid_t pid){
    int status;
    int counter = 0;
    struct user_regs_struct regs;
    unsigned long long instr;

    puts("Tiny debugger start....");

    wait(&status);      //wait for child to stop
    while(WIFSTOPPED(status)){
        counter ++;
        /*read child general registers*/
        ptrace(PTRACE_GETREGS, pid, 0, &regs);
        
        /*read an instruction going to be executed. 8 bytes enough for intel instruction set?*/
        instr = ptrace(PTRACE_PEEKDATA, pid, regs.rip, 0);
        if((regs.rip & 0xff000000) != 0xf7000000){
            if(cs_open(CS_ARCH_X86, CS_MODE_32, &handle)){
                perror("cs_open");
                return -1;
            }
            
        }
            printf("%u\tEIP=0x%08llx.\tInstr=0x%08llx.\n", counter, regs.rip, instr);

        /*step into*/
        ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
        wait(&status);
    }

    puts("Tiny debugger exit...");

}

int main(int argc, char **argv){
    pid_t child_pid;
    char **child_argv;

    if(argc < 2){
        fprintf(stderr, "Expect a program name !\n");
        return 1;
    }

    child_argv = malloc(8 * argc);
    for(int i = 0; i < argc - 1; i++)
        child_argv[i] = argv[i + 1];
    child_argv[argc] = NULL;

    child_pid = fork();
    if(child_pid == 0){
        load_executable_file(child_argv[0], child_argv);      //child goto execve a new program
    }else if(child_pid > 0){
        run_debugger(child_pid);          //parent wait for SIGCHLD wand prepare sending msg
    }else{
        perror("fork");
        return -1;
    }

    return 0;

}