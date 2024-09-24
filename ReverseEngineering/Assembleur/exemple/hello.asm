section .data
    myvar db 'Hello, world!',0

section .text
    global _start

write_hello:
    mov rax, 1          ; syscall numéro pour write
    mov rdi, 1          ; file descriptor 1 = stdout
    mov rsi, myvar      ; adresse du message
    mov rdx, 14         ; longueur du message
    syscall
    ret

_start:
    call write_hello    ; appel de la fonction write_hello
    mov rax, 60         ; syscall numéro pour exit
    xor rdi, rdi        ; code de retour 0
    syscall