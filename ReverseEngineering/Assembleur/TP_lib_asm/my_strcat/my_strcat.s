global my_strcat

my_strcat:
    push rdi
.loop:
    cmp byte [rdi], 0x0
    je .concat
    inc rdi
    jmp .loop
.concat:
    lodsb
    stosb
    cmp al, 0x0
    je .end
    jmp .concat
.end :
    pop rax
    ret