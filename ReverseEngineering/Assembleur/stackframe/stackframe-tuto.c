#include <stdio.h>
#include <string.h>

/*
 * gcc -ffreestanding -no-pie -std=c89 -fcf-protection=none -fno-stack-protector -O0 stackframe-tuto.c -o stackframe-tuto
 */
int child() {
    int i = 0x1234;
    short s = 12;
    long l = -2;
    char buf[19];
    strcpy(buf, "je suis child");
    puts(buf);
    return 0;
}

int main() {
    int a = 0xabcd;
    char buf[] = "je suis main";

    return child();
}
