def LFSR(n, reg, retro):
    # Masque pour n bits (pour s'assurer que seuls les n bits de poids faible sont pris en compte)
    mask = (1 << n) - 1
    
    # Calcul du bit de sortie (le bit de poids le plus faible)
    output_bit = reg & 1
    
    # Calcul du bit de rétroaction en appliquant le polynôme de rétroaction 'retro'
    feedback_bit = reg & retro
    feedback_bit ^= feedback_bit >> 32
    feedback_bit ^= feedback_bit >> 16
    feedback_bit ^= feedback_bit >> 8
    feedback_bit ^= feedback_bit >> 4
    feedback_bit ^= feedback_bit >> 2
    feedback_bit ^= feedback_bit >> 1
    feedback_bit &= 1  # Seuls le bit de poids le plus faible est conservé
    
    # Décalage du registre vers la droite et ajout du bit de rétroaction au bit de poids fort
    reg = (reg >> 1) | (feedback_bit << (n - 1))
    
    # Masque pour limiter à n bits
    reg &= mask
    
    return output_bit, reg

# Exemple d'utilisation
n = 16
reg = 0x5A
retro = 0b10110011  # Exemple de polynôme de rétroaction sur les 8 bits

for i in range(16):
    output_bit, reg = LFSR(n, reg, retro)
    print(f"Etape {i}: Registre: {bin(reg)}, Bit de sortie: {output_bit}")
