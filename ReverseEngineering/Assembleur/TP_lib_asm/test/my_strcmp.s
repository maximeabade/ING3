global my_strcmp

my_strcmp:
.loop:
    movzx   eax, byte [rdi]
    movzx   edx, byte [rsi]
    cmpsb
    jne     .end
    test    al, al
    jne     .loop
.end:
    sub     eax, edx
    ret