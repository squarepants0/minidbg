#include "utils.h"
// #include <unistd.h>

int main(int argc, char *argv[]){
    // if(argc < 2){
    //     fprintf(stderr, "Expecting program name Or PID\n");
    //     return -1;
    // }

    int  oc;
    const char *processPID = NULL, *targetPath = NULL;
    pid_t pid;
    while((oc = getopt(argc, argv, "p:f:h")) != -1){
        switch (oc)
        {
        case 'p':
            processPID = optarg;
            break;
        case 'f':
            targetPath = optarg;
            break;
        case 'h':
        default:
            puts("Usage: -p<pid> attach process Or -f<path2program>\n");
            exit(0);
        }
    }
    if(processPID && targetPath){
        puts("Cant set both!");
        exit(0);
    }
    /*first check if we got pid if we did check the process*/
    if(targetPath){
        pid = fork();
        if(pid == 0){
            //child process
            //execute tracee
            ptrace(PTRACE_TRACEME, 0, 0, 0);
            execl(targetPath, targetPath, NULL, NULL);
        }else if(pid > 0){
            //parent process
            //execute tracer
            puts("minidbg start up ....");
            Debugger dbg;
            dbg.d_brks = NULL;       /* important! initialize to NULL related to breakpoints` map*/
            dbg.d_name = targetPath;
            dbg.d_pid = pid;
            dbg_run(&dbg);
        }else{
            perror("fork.");
            return -1;
        }
    }else if(processPID){
        char path2proc[0x100];
        Debugger dbg;
        FILE* Fproc;

        puts("minidbg start up ....");
        sprintf(path2proc, "/proc/%s/cmdline", processPID);
        Fproc = fopen(path2proc, "r");
        if(Fproc == NULL){
            perror("fopen");
            return -1;
        }
        path2proc[fread(path2proc, 0x100, 1, Fproc)] = 0;
        
        dbg.d_brks = NULL;
        dbg.d_name = path2proc;
        dbg.d_pid = atoi(processPID);
        ptrace(PTRACE_ATTACH, dbg.d_pid, 0, 0);
        dbg_run(&dbg);
    }
    

    return 0;
}
