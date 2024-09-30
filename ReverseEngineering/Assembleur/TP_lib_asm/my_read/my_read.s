section .text
    global my_read
    extern __errno_location

my_read:
    xor eax, eax    ; syscall number for 'read' (0)
    syscall
    test eax, eax
    jns .end       ; jump if not sign (>= 0)
    
    neg eax
    push rax
    call __errno_location
    pop qword [rax]
    push -1
    pop rax

.end:
    ret
