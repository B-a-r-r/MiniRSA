from chiffrement import *
from utils import *

class CA:

    def __init__(self):
        self.keyDict:dict[str,dict] = {}
        #exemple: {"Alice":{"pub":xxxxx, "cert":xxxxx}, "Bob":{"pub":xxxxx, "cert":xxxxx}}
        self.set_key_pair()

    def recupClePub(self, msg:bytes, nom: str) -> bool:
        """
        Prend un message composé de la clé publique + 257 octets pour la signature (empreinte
        de la clé publique, chiffrée avec la clé privée de l'expéditeur).
        Renvoie True si la clé a bien été ajoutée et si la signature + empreinte sont valides,
        False sinon.
        """
        #split clé publique et empreinte
        clePubBytes, signature = utils.decompose_message(msg)
        
        #transforme la clé publique de bytes à tuple
        clePub:tuple[int] = utils.bytes_to_key(clePubBytes)
        #déchiffrer l'empreinte avec la clé publique
        empreinte = DechiffrageBytes(clePub, signature)
        
        #vérifie que la clé publique correspond à son empreinte
        if not utils.verifier_integrite(clePubBytes,empreinte):
            return False
        
        #enregistre la clé publique
        self.keyDict[nom] = {"pub":clePub}
        
        return True

    def generateCert(self, nom):
        assert (nom in self.keyDict.keys())
        
        #Chiffre la clé publique de nom avec la clé privée de CA (self.__pri)
        publ = self.keyDict[nom]["pub"]
        m:bytes = utils.key_to_bytes(publ)
        cert =  ChiffrageBytes(self.__pri, m)
        
        #enregistrer le certificat de nom ( self.keyDict[nom]["cert"] )
        self.keyDict[nom]["cert"] = cert

    def verifyCertificate(self, nom) -> bool:
        if nom not in self.keyDict.keys():
            return False
        if "pub" not in self.keyDict[nom].keys():
            return False
        if "cert" not in self.keyDict[nom].keys():
            return False
        
        #déchiffre le cert (self.keyDict[nom]["cert"]) avec la clé publique de CA (self.keys["pub"])
        cert = self.keyDict[nom]["cert"]
        clePubBytes = DechiffrageBytes(self.pub, cert)
        
        #transforme la clé publique de bytes à tuple
        clePub:tuple[int] = utils.bytes_to_key(clePubBytes)
        
        #vérifie que la clé publique correspond
        return self.keyDict[nom]["pub"][0] == clePub[0] and self.keyDict[nom]["pub"][1] == clePub[1]

    def getKeyDict(self):
        return self.keyDict
    
    def set_key_pair(self, coeffP: int = 1024, coeffQ: int = 1025):
        """
        Use functions from ras.py to generate a key pair for this CA. 
        """
        assert coeffP < coeffQ, "coeffP must be less than coeffQ"
        assert coeffP >= 1024, "coeffP must be ge than 1024"
        assert coeffQ >= 1025, "coeffQ must be ge than 1025"
        
        p = 0 
        q = 0
        
        while p == q:
            p = generationNombrePremier(2**coeffP, 2**coeffQ)
            q = generationNombrePremier(2**coeffP, 2**coeffQ)
        
        key_pair = create_key(p, q)
        
        self.pub = key_pair["pub"]
        self.__pri = key_pair["pri"] # cet attribut est privé