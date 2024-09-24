global my_strlen
my_strlen:
    xor eax, eax
.loop:
    cmp byte [rdi+rax], 0x0
    je .end
    inc rax
    jmp .loop

.end:
    ret

