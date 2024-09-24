si on termine de suite le programme, c est que c etait pas la bonne longueur de mdp
ce qui veut dire qu il faut tester des chaines de caractere de longueur croissante jusqua avoir un temps d attente satisfaisant

Une fois qu on a une attente satisfaisante, on peut tester les caracteres un par un, donc soit brut force

on a un sleep de 0.001 dans la boucle for i in range(len(Pin)) avec un return false si PINRentré(i) != Pin[i], un autre sleep sinon

Donc on a le bon password une fois qu on a un sleep de 0.002 * longueur du message


algo de base: 

savedPIN = "abcdefgh"

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


def trouverLongueur(PIN): 
    while True:
        start_time = time.time()
        Authentification(maString)
        end_time = time.time()
        elapsed_time = end_time - start_time
        if elapsed_time >= 0.002 * len(maString):
            return len(maString)
        maString += "a"


def trouverPIN(PIN):
    longueur = trouverLongueur(PIN)
    print("Longueur du mot de passe: ", longueur)
    password = ""
    for i in range(longueur):
        for c in "abcdefghijklmnopqrstuvwxyz":
            start_time = time.time()
            Authentification(password + c)
            end_time = time.time()
            elapsed_time = end_time - start_time
            if elapsed_time >= 0.002:
                password += c
                break
    print("Mot de passe: ", password)
    return password
