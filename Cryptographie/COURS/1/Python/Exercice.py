import time
savedPIN = "bonjour"


def Authentification(PIN):
    if len(PIN) != len(savedPIN):
        return False
    else:
        for i in range(len(PIN)):
            time.sleep(0.001)
            if PIN[i] != savedPIN[i]:
                return False
            time.sleep(0.001)
        return True


def catchExecTime(args):
    start = time.time()
    Authentification(args)
    end = time.time()
    return end - start


def findLen():
    stringInc = ""
    for i in range(1, 100):
        stringInc += "a"
        time = catchExecTime(stringInc)
        if time > 0.001:
            return i
    return 100


def trouverPIN():
    longueur = findLen()
    print("Longueur du mot de passe: ", longueur)
    password = ""
    for i in range(longueur):
        max_time = 0
        correct_char = ''
        for c in "abcdefghijklmnopqrstuvwxyz":
            start_time = time.time()
            Authentification(password + c + "a" * (longueur-len(password)-1))
            end_time = time.time()
            elapsed_time = end_time - start_time
            if elapsed_time > max_time:
                max_time = elapsed_time
                correct_char = c
        password += correct_char
        time.sleep(0.001)
    print("Mot de passe: ", password)
    return password


trouverPIN()
