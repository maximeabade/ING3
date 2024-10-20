from Crypto.Cipher import DES
from binascii import hexlify, unhexlify

def des_encrypt(message, key):
    # Création d'un objet de chiffrement DES avec la clé donnée
    des = DES.new(key, DES.MODE_ECB)
    
    # Chiffrement du message clair
    encrypted_message = des.encrypt(message)
    
    return encrypted_message

# Message clair et clé secrète
m_1 = b'\x00\x00\x00\x00\x00\x00\x00\x00'  # 0x0000000000000000 en bytes
m_2 = b'\x00\x00\x00\x00\x00\x00\x00\x01'  # 0x0000000000000001 en bytes
key = b'\x12\x34\x56\x78\x90\xAB\xCD\xEF'  # 0x1234567890ABCDEF en bytes

# Chiffrement
cipher_text = des_encrypt(m_1, key)

# Affichage du résultat en hexadécimal
print(f"Message clair 1: {hexlify(m_1).decode().upper()}")
print(f"Clé secrète : {hexlify(key).decode().upper()}")
print(f"Message chiffré 1: {hexlify(cipher_text).decode().upper()}")
print(f"Message clair 2: {hexlify(m_2).decode().upper()}")
print(f"Messaage chiffré 2: {hexlify(des_encrypt(m_2, key)).decode().upper()}")
