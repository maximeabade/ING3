global my_strcat

my_strcat:
    push rdi
.loop:
    cmp byte [rdi], 0x0
    je .concat
    inc rdi
    jmp .loop
.concat:
    movzx eax, byte [rsi]
    mov byte [rdi], al
    cmp al, 0x0
    je .end
    inc rsi
    inc rdi
    jmp .concat
.end :
    pop rax
    ret