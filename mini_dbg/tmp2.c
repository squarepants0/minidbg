#define CODE "\x55\x48\x8b\x05\xb8\x13\x00\x00\xe9\xea\xbe\xad\xde\xff\x25\x23\x01\x00\x00\xe8\xdf\xbe\xad\xde\x74\xff"

int main() {
    long a = 3;
    long b = 2;
    long c = a + b;
    a = 4;
    printf("sizeof_code: %d\n", sizeof(CODE));
}