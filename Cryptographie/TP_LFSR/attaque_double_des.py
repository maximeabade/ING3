from Crypto.Cipher import DES
from binascii import hexlify, unhexlify
from itertools import product

def des_encrypt(message, key):
    des = DES.new(key, DES.MODE_ECB)
    return des.encrypt(message)

def des_decrypt(encrypted_message, key):
    des = DES.new(key, DES.MODE_ECB)
    return des.decrypt(encrypted_message)

def double_des_encrypt(message, key1, key2):
    return des_encrypt(des_encrypt(message, key1), key2)

def double_des_decrypt(encrypted_message, key1, key2):
    return des_decrypt(des_decrypt(encrypted_message, key2), key1)

def meet_in_the_middle_attack(plain_text, cipher_text, key_space):
    # Dictionary to store intermediate encryption results
    intermediate_dict = {}

    # Encrypt the plain text with all possible keys and store the results
    for key1 in key_space:
        intermediate = des_encrypt(plain_text, key1)
        intermediate_dict[intermediate] = key1

    # Decrypt the cipher text with all possible keys and check for matches
    for key2 in key_space:
        intermediate = des_decrypt(cipher_text, key2)
        if intermediate in intermediate_dict:
            key1 = intermediate_dict[intermediate]
            return key1, key2

    return None, None

# Example usage
plain_text = b'\x00\x00\x00\x00\x00\x00\x00\x00'
cipher_text = double_des_encrypt(plain_text, b'\x12\x34\x56\x78\x90\xAB\xCD\xEF', b'\xFE\xDC\xBA\x98\x76\x54\x32\x10')

# Define a small key space for demonstration purposes
key_space = [bytes([i]) * 8 for i in range(256)]

key1, key2 = meet_in_the_middle_attack(plain_text, cipher_text, key_space)

if key1 and key2:
    print(f"Keys found: Key1 = {hexlify(key1).decode().upper()}, Key2 = {hexlify(key2).decode().upper()}")
else:
    print("Keys not found")