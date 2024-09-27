global my_read

my_read:
    xor eax, eax ; Syscall number 
    syscall
    test eax, eax
    js .bad
    ret
.bad:
    mov         r15, rax            ; save errno
    call        ___error            ; retrieve address to errno
    mov         [rax], r15          ; put errno in return value of __error (pointer to errno)
    mov         rax, -1
    ret