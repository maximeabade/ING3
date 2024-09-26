global my_toupper  

my_toupper:
    push rdi
    pop rax
    
    ; Verify that we are between 'a' and 'z'
    cmp al, 'a'
    jb done
    cmp al,'z'
    ja done

    ; Shift to ASCII upper
    sub al,0x20
done:   
    ret