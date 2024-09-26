global my_strcmp

my_strcmp:
.loop:
    movzx   eax, byte [rdi]
    movzx   edx, byte [rsi]
    cmp     al, dl
    jne     .end
    inc     rdi
    inc     rsi
    test    al, al
    jne     .loop
.end:
    sub     eax, edx
    ret