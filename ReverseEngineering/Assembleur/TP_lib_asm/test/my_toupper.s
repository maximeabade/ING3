global my_toupper  

my_toupper:
    movzx eax, byte dil
    
    ; Verify that we are between 'a' and 'z'
    cmp al,'a'
    jb done
    cmp al,'z'
    ja done

    ; Shift to ASCII upper
    sub al,0x20
done:   
    ret