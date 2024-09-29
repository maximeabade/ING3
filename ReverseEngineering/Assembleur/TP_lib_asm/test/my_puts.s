global my_puts

my_puts:
    xor edx, edx

.loop:  
	cmp byte [rdi + rdx], 0x0  
	je .next  
	inc edx  
	jmp .loop  

.next:
    push 1
    pop rax
    push rdi
    pop rsi
    push 1
    pop rdi
    syscall

    test eax, eax
    js .bad

    push 1
    pop rax
    push 1
    pop rdx
    push 0x0A
    push rsp
    pop rsi
    syscall
    pop rsi
    ret

.bad:
    push -1
    pop rax
    ret