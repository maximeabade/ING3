global my_memset  

my_memset:
    xor eax, eax
.loop:
    cmp eax, edx
    je .done
    mov byte [rdi + rax], sil
    inc eax
    jmp .loop
.done:
    mov rax, rdi
	ret