#include <stdio.h>
#include <string.h>

/*
 * gcc -ffreestanding -no-pie -std=c89 -fcf-protection=none -fno-stack-protector -O0 stackframe-tuto.c -o stackframe-tuto
 */
int child() {
    char buf1[24] = {0};
    int i = 0x123456;
    short s = 12;
    long l = -2;
    char buf2[19];
    strcpy(buf2, "Hello !");
    char *ptr = "bonjour";
    puts(buf2);
    return 0;
}

int main() {
    int a = 0xabcd;
    char buf[] = "je suis main";

    return child();
}
