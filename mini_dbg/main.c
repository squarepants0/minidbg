#include "utils.h"

int main(int argc, char *argv[]){
    if(argc < 2){
        fprintf(stderr, "Expecting program name.\n");
        return -1;
    }

    const char *name = argv[1];
    pid_t pid = fork();
    if(pid == 0){
        //child process
        //execute tracee
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        execl(name, name, NULL, NULL);
    }else if(pid > 0){
        //parent process
        //execute tracer
        puts("minidbg start up ....");
        Debugger dbg;
        dbg.d_brks = NULL;       /* important! initialize to NULL related to breakpoints` map*/
        dbg.d_name = name;
        dbg.d_pid = pid;
        dbg_run(&dbg);
    }else{
        perror("fork.");
        return -1;
    }

    return 0;
}
