global my_isalpha  

my_isalpha:
    or     edi, 0x20
    sub    edi, 'a' 
    cmp    edi, 'z'-'a'
    ja .non_alpha
    ret

.non_alpha:
    xor eax, eax
    ret