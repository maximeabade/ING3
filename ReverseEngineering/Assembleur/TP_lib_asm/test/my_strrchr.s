global my_strrchr

my_strrchr:
    xor eax, eax
.loop:
    cmp byte [rdi], sil
    jne .no_match
    push rdi
    pop rax
.no_match:
    cmp byte [rdi], 0x0
    je .end
    inc rdi
    jmp .loop
.end
    ret