import random
import math
import hashlib
import utils


def create_key(p: int, q: int) -> dict:
    """ 
    Crée une paire de clés RSA à partir de deux nombres premiers p et q.
    """
    assert testPrimalite(p-1, p), "p n'est pas premier"
    assert testPrimalite(q-1, q), "q n'est pas premier"
    
    res = {}
    n = p*q
    phi = (p-1)*(q-1)
    e=phi
    
    while(math.gcd(e,phi) != 1):
        e= random.randint(2,phi-1)

    d = pow(e, -1, phi)
        
    res["pub"] = (e,n)
    res["pri"] = (d,n)
    
    return res


def chiffrement(cle: tuple, m: int) -> int:
    """ 
    Utilise l'exponentiation modulaire pour chiffrer un message m avec une clé publique.
    """
    res = pow(m, cle[0], cle[1])
    return res


def dechiffrement(pri: tuple, c: int) -> int:
    """ 
    Inverse le chiffrement d'un message c avec une clé privée.
    """
    res = pow(c, pri[0], pri[1])
    return res

def testPrimaliteTotal(n: int) -> bool:
    """ 
    Test de primalité de n avec le test de Fermat pour les premiers nombres premiers.
    """
    L = [2,3,5,7,11]
    res = True
    
    for i in L:
        res = res and testPrimalite(i,n)
        
    return res

def testPrimalite(a: int, n: int) -> bool:
    """ 
    Test de primalité de n avec le test de Fermat 
    """ 
    return (pow(a,n-1,n) == 1)


def generationNombrePremier(a: int, b: int) -> int:
    """ 
    Génère un nombre premier entre a et b
    """
    res = random.randint(a,b)
    
    while(not testPrimaliteTotal(res)):
        res = random.randint(a,b)
        
    return res

def divide_bytes(ba: bytes, size: int) -> list[bytes]:
    """ 
    Divise un tableau de bytes en blocs de taille size.
    """
    res = [ba[i:i+size] for i in range(0, len(ba), size)]
    return res


def ChiffrageBytes(pub:tuple, m:bytes) -> bytes:
    """ 
    Chiffre une suite de bytes m avec une clé publique.
    """
    size = pub[1].bit_length() // 8

    divided_message = divide_bytes(m, size)
    integers = [utils.ba_to_int(i) for i in divided_message]

    #array de int chiffrés
    intarr = [chiffrement(pub, i) for i in integers]

    #array de bytes chiffrés
    bytarr = [utils.int_to_ba(i) for i in intarr]

    #array de bytes chiffrés et paddés pour qu'ils soient bien découpés par DéchiffrageBytes
    #(arrondis au supèrieur afin car le chiffrement peut changer le nombre de bytes du bloc de message mais le nombre de bytes ne dépassera pas l'arrondis au superieur)
    bytpadarr = [utils.pad_bytes(i, (pub[1].bit_length() + 7 ) //8 ) for i in bytarr]

    #byte array avec tous les bytes paddé joined en un message
    return b"".join(bytpadarr)

    
def DechiffrageBytes(pri:tuple, c:bytes):
    """ 
    Déchiffre une suite de bytes c avec une clé privée.
    """
    size = (pri[1].bit_length() + 7 ) //8 

    c_bytes_arr = divide_bytes(c, size)

    c_int_arr = [utils.ba_to_int(i) for i in c_bytes_arr]

    res = [dechiffrement(pri, i) for i in c_int_arr]
    bytes_value = [utils.int_to_ba(i) for i in res]
    return b"".join(bytes_value)

 
def signature_message(msg:bytes, cle:tuple[int]) -> bytes:
    """
    Renvoie une signature de 257 octets
    """
    empreinte = utils.empreinte_message(msg)
    return utils.pad_bytes(utils.int_to_ba(chiffrement(cle,utils.ba_to_int(empreinte))),257)
