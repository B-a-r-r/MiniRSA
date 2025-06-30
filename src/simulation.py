from User import User
from CA import CA
from time import sleep

if __name__ == "__main__":
    
    Ca = CA() 
    alice = User(name="Alice", ca=Ca)
    bob = User(name="Bob", ca=Ca)
    
    print(f"\n{alice.name} et {bob.name} souhaitent pouvoir s'envoyer des messages,"
          + "et sont soucieux que ceux-ci restent confidentiels, autenthiques et intègres.\n" \
          + "Début de la simulation..\n")
    
    alice.set_key_pair()
    print(f"\nPaire de clés privée/publique générée pour {alice.name}.")
    
    bob.set_key_pair()
    print(f"Paire de clés privée/publique générée pour {bob.name}.\n")
    
    alice.submit_key()
    sleep(1)
    print(f"\n{alice.name} a soumis sa clé publique au CA.")
    
    bob.submit_key()
    sleep(0.5)
    print(f"{bob.name} a soumis sa clé publique au CA.\n")
    
    
    print(f"\nLe CA a généré un certificat pour les deux parties, leur clé publique sont authentifiées sur le réseau.")
    print(f"Au début, les boîtes de réception et d'envoi d'{alice.name} et de {bob.name} sont vides : ")
    print(alice.display_inbox())
    print(alice.display_sent_messages())
    print()
    print(bob.display_inbox())
    print(bob.display_sent_messages())
    
    message = str(input(f"\nVous êtes {alice.name}, entrez votre message pour {bob.name}: "))
    print(alice.send_message(receiver=bob, message=message))
    
    print(f"\nA la fin de la simulation, les boîtes de réception et d'envoi d'{alice.name} et de {bob.name} sont : ")
    print(alice.display_sent_messages())
    print(bob.display_inbox())
    
    
    
    
    
    
    