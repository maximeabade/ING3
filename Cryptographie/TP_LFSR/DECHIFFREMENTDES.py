from Crypto.Cipher import DES
from binascii import hexlify, unhexlify

def des_decrypt(encrypted_message, key):
    # Création d'un objet de déchiffrement DES avec la clé donnée
    des = DES.new(key, DES.MODE_ECB)
    
    # Déchiffrement du message chiffré
    decrypted_message = des.decrypt(encrypted_message)
    
    return decrypted_message

# Messages chiffrés et clé secrète
cipher_text_1 = unhexlify('AAAAAAAAAAAABAAA')  # Exemple de message chiffré 1 en hexadécimal
cipher_text_2 = unhexlify('AAAAAAAAAAAAAAAA')  # Exemple de message chiffré 2 en hexadécimal
key = b'\x12\x34\x56\x78\x90\xAB\xCD\xEF'  # 0x1234567890ABCDEF en bytes

# Déchiffrement
decrypted_message_1 = des_decrypt(cipher_text_1, key)
decrypted_message_2 = des_decrypt(cipher_text_2, key)

# Affichage du résultat en hexadécimal
print(f"Message chiffré 1: {hexlify(cipher_text_1).decode().upper()}")
print(f"Clé secrète : {hexlify(key).decode().upper()}")
print(f"Message déchiffré 1: {hexlify(decrypted_message_1).decode().upper()}")
print(f"Message chiffré 2: {hexlify(cipher_text_2).decode().upper()}")
print(f"Message déchiffré 2: {hexlify(decrypted_message_2).decode().upper()}")