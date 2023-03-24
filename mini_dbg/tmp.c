#include <stdlib.h>
#include "linenoise/linenoise.h"
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/user.h>
struct user_regs_struct reg;

void foo(int a, int b){
    printf("0x%lx\t0x%lx\t\n", &a, a);
}

void foo_size(){
    printf("ll: %d\tul: %d\n", sizeof(long long), sizeof(unsigned long));
}

void foo_atol(char *str){
    printf("hex for atol: 0x%llx\n", atoll(str));
}

void mapsTest(){
    FILE *maps_fd = fopen("/proc/self/maps", "r");
    unsigned long a, b;
    char perm[64], name[64];
    while(fscanf(maps_fd, "%lx-%lx %4s %*[0-9a-f] %*d:%*d %*d%[^\n]", &a, &b, perm, name) != EOF){
        for(int i = 0; i < 64;i++){
            if(name[i] == ' ') name[i] = '\x00';
            else {
                strcpy(name, &name[i]);
                break; 
            }
        }
        printf("%lx-%lx %s %s\n", a, b, perm, name);
    }
    
        
}

int main(){
    mapsTest();
    foo(1, 2);
    foo_size();
    foo_atol("1234");
    printf("len: %d\n", strlen(calloc(0x10, 1)));
    char *line = linenoise("test ");
    printf("size: %d\n", strlen(line));
    line = linenoise("test ");
    printf("0x%08lx\n", strtoul("0x123", NULL, 16));
    return 0;
}
