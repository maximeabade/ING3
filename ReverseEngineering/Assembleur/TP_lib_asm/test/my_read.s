global my_read
extern	__errno_location

my_read:
    xor eax, eax ; Syscall number 
    syscall
    test eax, eax
    jns .good
.bad:
    neg eax
    push rax
    pop rdi
    call __errno_location
    mov [rax], edi
    push -1
    pop rax
.good
    ret