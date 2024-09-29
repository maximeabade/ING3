global my_strcat

my_strcat:
    push rdi
    xor eax, eax
    repne scasb
    dec rdi
.concat:
    lodsb
    stosb
    test al, al
    je .end
    jmp .concat
.end :
    pop rax
    ret