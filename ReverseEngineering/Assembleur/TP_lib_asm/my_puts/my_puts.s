global my_puts

section .data
   line_ret  db 0x0A, 1

section .text
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

    test rax, rax
    js .bad

    push 1
    pop rax
    push line_ret
    pop rsi
    push 1
    pop rdx
    syscall

    ret

.bad
    push -1
    pop rax
    ret