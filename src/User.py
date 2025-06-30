from chiffrement import *
from utils import *
from CA import CA
import User

class User:
    def __init__(self, name: str, ca: CA):
        assert ca!= None, "Certificate Authority must be defined"
        
        self.name = name
        self.key_pair = {}
        self.CA = ca
        self.sent_messages = ["*no messages sent*"]
        self.inbox_messages = ["*no messages received*"]
        
    def set_key_pair(self, coeffP: int = 1024, coeffQ: int = 1025):
        """
        Génère une paire de clés RSA pour l'utilisateur, avec des coefficients de taille spécifiée.
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
        
        self.key_pair = key_pair
    
    def send_message(self, message: str, receiver: User) -> str:
        """
        Permet à l'utilisateur d'envoyer un message à un autre utilisateur.
        """
        if (self.sent_messages[0] == "*no messages sent*"):
            self.sent_messages.pop(0)
        self.sent_messages.append(message)
            
        cipher_text = ChiffrageBytes(receiver.key_pair["pub"], self.sent_messages[len(self.sent_messages)-1].encode('utf-8'))
        footprint = empreinte_message(cipher_text)
        signature = ChiffrageBytes(self.key_pair["pri"], footprint)
        composed = compose_message(cipher_text, signature)
        
        return(f"\n{self.name} a envoyé un message à {receiver.name} : \n"
          + f"- texte en claire : \"{message}\"\n"
          + f"- message chiffré : \"{cipher_text}\"\n"
          + f"- empreinte : \"{footprint}\"\n"
          + f"- signature : \"{signature}\"\n"
          + "\n" \
          + receiver.receive_message(composed, self))
        
    def submit_key(self) -> bool: 
        """ 
        Soumet la clé publique de l'utilisateur à l'autorité de certification.
        """
        keyBytes = key_to_bytes(self.key_pair['pub'])
        pub_key_footprint = empreinte_message(keyBytes)
        signature = ChiffrageBytes(self.key_pair["pri"], pub_key_footprint)
        composed = compose_message(keyBytes, signature)
        
        if not self.CA.recupClePub(composed,self.name):
            raise Exception(f"The public key could not be registered by the CA, for {self.name}.")
        
        self.CA.generateCert(self.name)
        
        return self.CA.verifyCertificate(self.name)

    def receive_message(self, full_message: bytes, sender: User) -> str:
        """ 
        Permet à l'utilisateur de recevoir un message d'un autre utilisateur.
        """
        if (self.inbox_messages[0] == "*no messages received*"):
            self.inbox_messages.pop(0)
        
        msg, signature = decompose_message(full_message)

        deciphered_message = DechiffrageBytes(self.key_pair["pri"],msg)

        if not self.CA.verifyCertificate(sender.name):
            print(f"verifyCertificate({sender.name}) a échoué")
            raise Exception(f"Authenticity verification failed for {sender.name}'s message to {self.name}.")
        
        senderPub = self.CA.getKeyDict()[sender.name]["pub"]

        empreinte = DechiffrageBytes(senderPub,signature)
        if not verifier_integrite(msg,empreinte):
            print(f"vérification d'intégrité/d'authenticité a échoué")
            raise Exception(f"Integrity verification failed for {sender.name}'s message to {self.name}.")
        
        self.inbox_messages.append(deciphered_message)
        
        return(f"\n{self.name} a reçu un message de {sender.name} : \n"
          + f"- message chiffré : \"{full_message}\"\n"
          + f"- empreinte : \"{empreinte}\"\n"
          + f"- signature : \"{signature}\"\n"
          + f"- texte en claire : \"{deciphered_message}\"\n")
    
    def display_inbox(self) -> str:
        repr = "\n-------------------------------\n" \
                + "User " + self.name + " INBOX messages: \n"
        
        for message in self.inbox_messages:
            repr += "=>" + str(message) + "\n"

        repr += "-------------------------------"
        
        return repr
        
    def display_sent_messages(self) -> str:
        repr = "\n-------------------------------\n" \
                + "User " + self.name + " SENT messages: \n"
        
        for message in self.sent_messages:
            repr += "=>" + str(message) + "\n"

        repr += "-------------------------------"
        
        return repr