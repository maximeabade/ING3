from pwn import *

# Démarre le processus local
p = process('./binaire')

# Envoie un motif cyclique de taille 100 avec des séquences de 8 octets
p.sendline(cyclic(100, n=8))
p.wait()

# Analyse le corefile
core = p.corefile
rip = core.read(core.rsp, 8)  # Récupère les 8 octets au sommet de la stack
offset = cyclic_find(rip, n=8)  # Cherche l'offset avec n=8
print(f"Offset: {offset}")
