global my_isalpha  

my_isalpha:
    push rdi
    pop rax
    and al, ~32
    sub al, 'A'
    cmp al, 26
    sbb al, al
    ret