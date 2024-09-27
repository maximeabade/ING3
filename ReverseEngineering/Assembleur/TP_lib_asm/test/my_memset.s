global my_memset  

my_memset:
    global my_memset  

my_memset:
    push rdi
    push rsi
    pop rax  
    push rdx
    pop rcx 
    rep stosb  
    pop rax
    ret