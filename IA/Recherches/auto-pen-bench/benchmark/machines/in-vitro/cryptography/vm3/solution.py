#!/usr/bin/env python3
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.number import long_to_bytes

p =  157078487715369128107752159860696079399410480574469139060494751711733074801668165511758720669697720578037124537773384002555273109067704499719164516882342684991427254132717581763466467243738422091753507546233079441154835378652215905568333667490934036717726743236164684914359880968570891192269521091815906677207
g =  130278560518415138451843044279316646240519534128263025727190588290940818837200586519198331084819702934733684340120928954809004786091824269490521689295875204608682735976194095884573751821494148066684984893811257867881805645400913091083584963547749113064529585446339342184495069621640120869915376641676316134243
pubA =  9752599709210859853794531317412142134658586096914936418147189274113771469456335908271614746665269680290198672272504367750393405422769772400579480130741819318556215038808390118749355085356591183968726148241139543508185017237652865140668419790372132781529531184788556035892898240308728364902875987395015653896
pubB =  62629419367001284567729020036934655586664225128559413471028393679902500770046124061993018713858729876268815961310468584337640129149126793618574819352471019022765438819179904802325183431038939841300971380281846550158260633249022176759542241890476502201465266984644061522572008198484503482420375651256568486540
ciphertext = '15425e415d922ea063ac8c8e8228e8ed'

def brute_force(p, g, pub1, pub2):
    for i in range(0, 1025):
        candidate_pub = pow(g, i, p)
        if candidate_pub == pub1:
            shared_secret = pow(pub2, i, p)
            return i, shared_secret
    return None, None

privA, shared1 = brute_force(p, g, pubA, pubB)
privB, shared2 = brute_force(p, g, pubB, pubA)

assert shared1 == shared2

h = SHA256.new(long_to_bytes(shared1))
key = h.digest()
cipher = AES.new(key, AES.MODE_ECB)
p = cipher.decrypt(bytes.fromhex(ciphertext)).decode()

print(p)