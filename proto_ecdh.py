import typing
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography import exceptions
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import binascii
import os

def ed_key (local_pss:typing.Optional[str] = None):
    ed_prv_key = Ed25519PrivateKey.generate()
    ed_pub_key = ed_prv_key.public_key()
    if local_pss == None:
        ed_prv_bytes = ed_prv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    else:
        ed_prv_bytes = ed_prv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(local_pss.encode())
        )
    ed_pub_bytes = ed_pub_key.public_bytes (
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return (ed_prv_bytes, ed_pub_bytes)

def make_sign (ed_prv_bytes:bytes, prv_pss:str, data:bytes):
    try:
        loaded_ed_key = serialization.load_pem_private_key(
            ed_prv_bytes,
            prv_pss.encode()
        )
        assinatura = loaded_ed_key.sign(data)
        return (assinatura, True)
    except:
        return (b'pass_error', False)

def sign_ver (ed_pub_key:bytes, assin:bytes, data:bytes):
    try:
        loaded_pb_key = serialization.load_pem_public_key(
            ed_pub_key
        )
        loaded_pb_key.verify(assin, data)
        return True
    except exceptions.InvalidSignature:
        return False

def key_gen (key_pss:typing.Optional[str] = None):
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()
    if key_pss == None:
        private_key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    else:
        private_key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(key_pss.encode())
        )
    public_key_bytes = public_key.public_bytes (
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    key_ring = [private_key_bytes, public_key_bytes]

    return key_ring

def final_key_usr(private_key, peer_public_key):
    shared_key = private_key.exchange(peer_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(shared_key)
    return derived_key

def in_cryp(data:bytes, key:bytes):
    iv = os.urandom(12)
    cryp = Cipher(
            algorithms.AES(key), 
            modes.GCM(iv)
        ).encryptor()
    info_sec = cryp.update(data) + cryp.finalize()
    return (iv, info_sec, cryp.tag)

def de_cryp(data:bytes, key:bytes, iv:bytes, tag:bytes):
    decryp = Cipher(
            algorithms.AES(key), 
            modes.GCM(iv,tag)
        ).decryptor()
    try:
        result = decryp.update(data) + decryp.finalize()
    except:
        print('Bad key!')
    return result

def import_priv_key (priv_kbytes:bytes, passwd:typing.Optional[str] = None):
    try:
        if passwd == None:
            loaded_priv_key = serialization.load_pem_private_key(
                priv_kbytes,
                password=None
            )
        else:
            loaded_priv_key = serialization.load_pem_private_key(
                priv_kbytes,
                passwd.encode()
            )
        return loaded_priv_key
    except:
        print('Invalid Password!')
        return None

def cryp_key(priv_key:X25519PrivateKey, pub_key:bytes):
        loaded_pub_key = serialization.load_pem_public_key(
            pub_key,
        )
        shar_key = priv_key.exchange(loaded_pub_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(shar_key)
        return derived_key