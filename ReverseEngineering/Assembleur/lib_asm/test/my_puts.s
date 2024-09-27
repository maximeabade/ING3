global my_puts

section .data
   line_ret  db 0xA, 1

section .text
my_puts:
    xor edx, edx

.loop:  
	cmp byte [rdi + rdx], 0x0  
	je .next  
	inc edx  
	jmp .loop  

.next:
    mov rax, 1 ; Syscall number 
    mov rsi, rdi ; String Buffer
    mov rdi, 1 ; To stdout
    syscall
    cmp rax, 0
    jne .bad

    mov rax, 1 ; Syscall number 
    mov rsi, line_ret
    mov rdx, 1
    syscall
    ret

.bad
    mov eax, 0xfffffff7
    ret