#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include "tpl/src/tpl.h"
#include "utils.h"

int main(){
    struct reg_map reg_maps[27];        //"S($(iU)U)#", n_regs
    struct mem_map *mapHeader = NULL, *mem_list, mem_tmp;           //"A(S(UUcs))"
    tpl_node *snapshotND;
    tpl_bin tb;                             //"A(B)"
    snapshotND = tpl_map("S($(is)U)#A(S(UUus))A(B)", reg_maps, 27, &mem_tmp, &tb);
    tpl_load(snapshotND, TPL_FILE, "snap.bin");

    tpl_unpack(snapshotND, 0);
    puts("----------------------register----------------------");
    for(int i = 0; i < 27; i++){
        printf("name: %s\tvalue: 0x%08lx\n", reg_maps[i].reg_des.name, reg_maps[i].value);
    }
    puts("----------------------register----------------------");

    while(tpl_unpack(snapshotND, 1) > 0){
        // printf("name: ")
        if(strlen(mem_tmp.name) == 0) printf("name: null\t");
        else printf("name: %s\t", mem_tmp.name);
        printf("address: 0x%08lx\tsize: 0x%08lx\tperm: %d\n", mem_tmp.addr, mem_tmp.size, mem_tmp.perm);
    }

    return 1;
}