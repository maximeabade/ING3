from typing import Counter
import os


# EXO 1


Mytext = "uj lahycxpajyqrn nbc dwn mrblryurwn yaxkjkunvnwc jdbbr jwlrnwwn zdn un knbxrw mn lxvvdwrzdna. yxdacjwc ln w nbc yjb uj bndun vjwrnan mn cajwbvnccan bnlancnvnwc mn u rwoxavjcrxw. mnsj jd e n brnlun jesl, un panl qnaxmxcn mnlarc, mjwb bnb lqaxwrzdnb mnb pdnaanb nwcan unb panlb nc unb ynabnb, dwn vncqxmn cxdc jdcjwc rwpnwrndbn zd ncxwwjwcn yxda ljlqna mnb vnbbjpnb : u rmnn nbc mn ajbna uj cncn m dw nblujen mn lxworjwln, mn cjcxdna un vnbbjpn bnlanc bda bxw lajwn ydrb m jccnwman zdn unb lqnendg anyxdbbnwc, mrbbrvdujwc jrwbr un vnbbjpn. u nblujen yxdejrc juxab mnureana un vnbbjpn. un mnbcrwjcjran w jejrc juxab zd j ajbna mn wxdenjd un lajwn mn u nblujen yxda yxdexra uran un vnbbjpn. ru wn ojuujrc yjb ncan yanbbn... u jac mn mrbbrvduna un bdyyxac vnvn m dw vnbbjpn yxda un anwman bnlanc nbc jyynun bcnpjwxpajyqrn."
# Le but va etre de le dechiffrer, on sait que c est un cryptage de cesar
# On va donc essayer de trouver la clef de dechiffrement

# On va commencer par calculer la frequence d'apparition des lettres


def decrypt_cesar(ciphertext, shift):
    decrypted_text = ""
    for char in ciphertext:
        if char.isalpha():
            shifted = ord(char) - shift
            if char.islower():
                if shifted < ord('a'):
                    shifted += 26
                decrypted_text += chr(shifted)
            elif char.isupper():
                if shifted < ord('A'):
                    shifted += 26
                decrypted_text += chr(shifted)
        else:
            decrypted_text += char
    return decrypted_text


def frequency_analysis(text):
    # Count the frequency of each letter in the text
    text = text.replace(" ", "").replace("\n", "")
    counter = Counter(text)
    total_chars = sum(counter.values())
    frequencies = {char: count / total_chars for char,
                   count in counter.items()}
    return frequencies


# Calculate the frequency of each letter in the ciphertext
frequencies = frequency_analysis(Mytext)
# print("Frequencies:", frequencies)

# Assuming the most frequent letter in the ciphertext corresponds to 'e' in English
most_frequent_letter = max(frequencies, key=frequencies.get)
shift = (ord(most_frequent_letter) - ord('e')) % 26

# Decrypt the text using the calculated shift
# decrypted_text = decrypt_cesar(Mytext, shift)
# print("Decrypted Text:", decrypted_text)


# On utilise la fréquence des lettres pour déterminer celles qui reviennent le plus souvent puis on essaye avec ce qu on sait de la langue francais en terme d apparition de lettres

# Le chiffrement de cesar marche avec une coresspondance entre les lettres du clair et du crypté, on peut donc utiliser la fréquence des lettres pour déterminer la lettre la plus fréquente et donc la lettre qui correspond à e en francais

# Ca couterait au pire des cas 25! a priori


# EXO 2

# il existe 25! clés possibles ce qui est assez pour faire planter je epsne l ordi le plus puissant du monde (sauf les quantiques)

def chiffrementSubstitution(text, key):
    # key est le tableau a une dimmension des correspondances, tel que key[0] contienne la valeur pour a
    encryptedString = ""
    # pour chaque caractere dans le texte, on chope sa valeur ascii-valeur ascii de a et ca donne l index a chercher dans key
    for char in text:
        asciichar = ord(char)
        if (asciichar >= 97 and asciichar <= 122):
            encryptedString += key[(asciichar-97)]
        else:
            encryptedString += char
    return encryptedString


def dechiffrementSubstitution(text, key):
    # key est le tableau a une dimmension des correspondances inverses, tel que key[0] contienne la valeur pour a
    decryptedString = ""
    # pour chaque caractere dans le texte, on chope sa valeur ascii-valeur ascii de a et ca donne l index a chercher dans key
    inverse_key = {v: chr(i + 97) for i, v in enumerate(key)}
    for char in text:
        if char.isalpha() and char.islower():
            decryptedString += inverse_key[char]
        else:
            decryptedString += char
    return decryptedString


def keygen(text):
    # Frequency analysis of the text
    frequencies = frequency_analysis(text)
    # Sort letters by frequency in descending order
    sorted_letters = sorted(frequencies, key=frequencies.get, reverse=True)
    # Most frequent letters in French (in order)
    most_frequent_french = 'esaitnrulodcmpévqfbghjxyzwk'
    # Generate the key based on frequency analysis
    key = [''] * 26
    for i, letter in enumerate(sorted_letters):
        if 'a' <= letter <= 'z':  # Ensure the letter is a lowercase alphabet
            key[ord(letter) - ord('a')] = most_frequent_french[i]
    return key


# lecture du fichier 
textFRlocation = "./le_petit_prince_antoine_de_saint_exupery.txt"
textENlocation = "./macbeth_shakespeare.txt"
textFR = ""
textEN = ""
with open(textFRlocation, 'r', encoding='utf-8') as file:
    textFR = file.read()
with open(textENlocation, 'r', encoding='utf-8') as file:
    textEN = file.read()

#key = keygen(textFR)
#print("Generated Key:", key)
# Encrypt and decrypt using the generated key
#encrypted_text = chiffrementSubstitution(textFR, key)
#print("Encrypted Text in French:", encrypted_text)
#decrypted_text = dechiffrementSubstitution(encrypted_text, key)
#print("Decrypted Text in French:", decrypted_text)


# detection de la langue 
# on veut faire une focntion qui a partir de la frequence d apparition des lettres dans un text reussit a dire si il est en Francais ou en Anglais

def letter_frequency_table(text):
    frequencies = frequency_analysis(text)
    sorted_frequencies = sorted(frequencies.items(), key=lambda item: item[0])
    print("Letter Frequencies:")
    for letter, freq in sorted_frequencies:
        print(f"{letter}: {freq:.4f}")


# Generate the frequency table for the French text
letter_frequency_table(textFR)
letter_frequency_table(textEN)


def detect_language(frequencies):
    # Most frequent letters in French and English (in order)
    most_frequent_french = 'esaitnrulodcmpévqfbghjxyzwk'
    most_frequent_english = 'etaoinshrdlcumwfgypbvkjxqz'

    # Calculate the score for French and English
    score_french = 0
    score_english = 0

    sorted_letters = sorted(frequencies, key=frequencies.get, reverse=True)

    for i, letter in enumerate(sorted_letters):
        if letter in most_frequent_french:
            score_french += most_frequent_french.index(letter)
        if letter in most_frequent_english:
            score_english += most_frequent_english.index(letter)

    return 'French' if score_french < score_english else 'English'


# Detect the language of the French text
frequencies_fr = frequency_analysis(textFR)
language_fr = detect_language(frequencies_fr)
print("Detected Language for French text:", language_fr)

# Detect the language of the English text
frequencies_en = frequency_analysis(textEN)
language_en = detect_language(frequencies_en)
print("Detected Language for English text:", language_en)



# attaque par analyse frequentielle en francais
text2decrypt = "uc pxtch puixxdix ? yixlkcci ytx ft puixxi ci hibdicj pxtch.ft puixxi hil ijkdfil"

# Generate the key based on the frequency analysis of the French text
key = keygen(textFR)
print("Generated Key:", key)

# Decrypt the given text using the generated key
decrypted_text = dechiffrementSubstitution(text2decrypt, key)
print("Decrypted Text:", decrypted_text)




