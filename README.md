# SAE 3.09 miniRSA
<sup>_sujet:_ https://ramet.gitlab.io/r3.09-crypto/minirsa.pdf </sup><br/>
<br/>
Dans le cadre d'une simulation d'échanges sur le réseau, on souhaite implémenter un version sommaire du protocole RSA. Alice et Bob doivent communiquer de façon sécurisée, leurs messages doivent rester confidentiels, intègres et authentiques.<br/>
<br/>
<ins>NB</ins>: on simulera une telle situation par des échanges entre des classes Python.

## Fonctionnalités à développer 
- Signer une information grâce à une empreinte. :warning: 
- Générer des certificats, signés par une autorité de certification (CA), pour chaque protagoniste de la simulation. :warning:
- Vérifier la pseudo-primalité d’un entier avec le test de ![Miller-Rabin](https://fr.wikipedia.org/wiki/Test_de_primalit%C3%A9_de_Miller-Rabin), plus robuste que celui de Fermat. 
- Permettre l'utilisation du miniRSA sur du texte.

## Tutoriel de lancement
Il faut lancer simulation.py

\*:warning: _requis_. 

