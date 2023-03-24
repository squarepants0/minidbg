#include <unistd.h>

void sleeper(unsigned long t){
    int a, b, c, d, e;
    a = b = c = d = e = t;
    while(a > 0) a--;
    while(b > 0) b--;
}


int main(int argc, char *argv[]){
    int time0 = 10000;
    int time1 = 100000;
    int oc;
    while((oc = getopt(argc, argv, "p:f:")) != -1){
        switch(oc){
            case 'p':
                printf("[p] %s\n", optarg);
                break;
            case 'f':
                printf("[f] %s\n", optarg);
                break;
        }
    }
    while(time0 > 0) time0--;
    while(time1 > 0) time1--;
    sleeper(time0);
    while(1);
    return 1;
}