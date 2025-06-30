import hashlib

def int_to_ba(x: int) -> bytes:
    """ 
    Convertit un entier en bytes en big-endian.
    """
    return x.to_bytes(length=(x.bit_length() + 7) // 8,byteorder="big")

def ba_to_int(b: bytes) -> int:
    """ 
    Convertit des bytes en entier en big-endian.
    """
    return int.from_bytes(b,byteorder="big")

def empreinte_message(msg:bytes) -> bytes:
    """ 
    Renvoie l'empreinte d'un message avec SHA-256.
    """
    return hashlib.sha256(msg).digest()

def verifier_integrite(msg:bytes, hash:bytes) -> bool:
    """ 
    Vérifie que l'empreinte d'un message correspond à un hash donné.
    """
    return empreinte_message(msg) == hash

def pad_bytes(b: bytes, bytesize: int) -> bytes:
    """
    Pad des bytes (rajoute des 0s à la fin) en big-endian.
    """
    assert len(b) <= bytesize
    return bytes([0 for _ in range(bytesize-len(b))]) + b

def compose_message(msg:bytes, signature:bytes) -> bytes:
    """
    Compose un message et sa signature dans un seul code.
    message composé: 2 octets pour la taille du message, le message, la signature.
    """
    return len(msg).to_bytes(2, byteorder='big') + msg + signature

def decompose_message(full_msg:bytes) -> tuple[bytes,bytes]:
    """ 
    Decompose un code coomplet dans un tuple 
    contenant le message et son signature.
    """
    msg_len = ba_to_int(full_msg[:2])
    return full_msg[2:2+msg_len], full_msg[2+msg_len:]

def key_to_bytes(key: tuple[int]) -> bytes:
    """ 
    Convertit une clé en bytes.
    """
    e_or_d, n = key
    
    e_or_d_bytes = int_to_ba(e_or_d)
    n_bytes = int_to_ba(n)

    return len(e_or_d_bytes).to_bytes(2, byteorder='big') + len(n_bytes).to_bytes(2, byteorder='big') + e_or_d_bytes + n_bytes

def bytes_to_key(keyBytes: bytes) -> tuple[int]:
    """ 
    Convertit des bytes en une clé.
    """
    assert len(keyBytes) >= 4, "keyBytes too short"
    e_or_d_size_bytes, n_size_bytes, rest_bytes = keyBytes[:2], keyBytes[2:4], keyBytes[4:]
    
    e_or_d_size = ba_to_int(e_or_d_size_bytes)
    n_size = ba_to_int(n_size_bytes)
    
    e_or_d_bytes, n_bytes = rest_bytes[:e_or_d_size], rest_bytes[e_or_d_size: (e_or_d_size+n_size)]
    e_or_d = ba_to_int(e_or_d_bytes)
    n = ba_to_int(n_bytes)

    return (e_or_d,n)