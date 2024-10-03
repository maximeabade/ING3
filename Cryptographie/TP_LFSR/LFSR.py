import sys

def lfsr(n: int, reg: int, retro: int):
    if (n > 64):
        return None
    
    new_bit = bin(reg & retro).count('1') % 2
    res = reg & 0x1
    reg = (reg >> 1) | (new_bit << (n - 1))

    return (res, reg)

def gen_key(size_key: int, n: int, reg: int, retro: int) -> int:
    key = 0
    for i in range(size_key):
        state = lfsr(n, reg, retro)
        reg = state[1]
        key = key << 1 | state[0]

    return key

def encryptLFSR(input_string: str, n: int, reg: int, retro: int) -> bytes:
    key = gen_key(len(input_string) * 8, n, reg, retro)

    # Convertir la chaîne en bytes
    byte_string = input_string.encode('utf-8')

    # Initialiser une liste pour stocker les résultats
    result = []
    
    # Effectuer le XOR pour chaque octet
    for byte in byte_string:
        number = key & 0xFF
        key = key >> 8
        xored_byte = byte ^ number
        #print("Number: " + bin(number) + " | byte: " + bin(byte) + " | xroed: " + bin(xored_byte))
        result.append(xored_byte)
    
    # Convertir le résultat en bytes puis en chaîne
    #print(bytes(result))
    return bytes(result)

def decryptLFSR(input_string: bytes, n: int, reg: int, retro: int) -> str:
    key = gen_key(len(input_string) * 8, n, reg, retro)

    # Initialiser une liste pour stocker les résultats
    result = []
    
    # Effectuer le XOR pour chaque octet
    for byte in input_string:
        number = key & 0xFF
        key = key >> 8
        xored_byte = byte ^ number
        #print("Number: " + bin(number) + " | byte: " + bin(byte) + " | xroed: " + bin(xored_byte))
        result.append(xored_byte)
    
    # Convertir le résultat en bytes puis en chaîne
    return bytes(result).decode('utf-8', errors='replace')

def main() -> None:
    # Valeur initial
    n = 8
    reg = 0x5A
    retro = 0b10110011

    for i in range(16):
        state = lfsr(n, reg, retro)
        reg = state[1]

    n = 8
    reg = 0x5A
    retro = 0b10110011

    word = "hello world!"
    print(encryptLFSR(word, n, reg, retro).decode('utf-8', errors='replace'))
    print(decryptLFSR(encryptLFSR(word, n, reg, retro), n, reg, retro))
    assert(decryptLFSR(encryptLFSR(word, n, reg, retro), n, reg, retro) == word)


if __name__ == "__main__":
    main()