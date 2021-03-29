import base64
from typing import Optional, Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption, BestAvailableEncryption
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .util import load_key


"""
Helper classes for PEM-encoded RSA and Ed25519 keys, expected format is X.509 SubjectPrivate/PublicKeyInfo
(PKCS#8, marked by -----BEGIN/END PUBLIC/PRIVATE KEY-----) though some methods will also accept RSA keys
(PKCS#1, marked by -----BEGIN/END RSA PUBLIC/PRIVATE KEY-----) as input. Fingerprinting uses OpenSSH format 
so the results match ssh-keygen output, which is used in a lot of places online.
"""


class PrivateKeyHelper:
    @staticmethod
    def from_bytes(key: bytes, password: Optional[bytes]=None) -> Union[RSAPrivateKey, Ed25519PrivateKey]:
        if len(key) > 0 and key[:1] != b'-':
            key = b'-----BEGIN PRIVATE KEY-----\n' + key + b'\n-----END PRIVATE KEY-----\n'
        return load_key(key, True, password)

    @staticmethod
    def from_string(key: str, password: Optional[bytes]=None) -> Union[RSAPrivateKey, Ed25519PrivateKey]:
        return PrivateKeyHelper.from_bytes(key.encode('utf-8'), password)

    @staticmethod
    def from_file(filename: str, password: Optional[bytes]=None) -> Union[RSAPrivateKey, Ed25519PrivateKey]:
        with open(filename, 'rb') as f:
            return PrivateKeyHelper.from_bytes(f.read(), password)

    @staticmethod
    def to_bytes(key: Union[RSAPrivateKey, Ed25519PrivateKey], strip: bool=False, password: Optional[bytes]=None) -> bytes:
        b = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption() if password is None else BestAvailableEncryption(password))
        if password is None and strip:
            b = b. \
                replace(b'-----BEGIN PRIVATE KEY-----', b''). \
                replace(b'-----END PRIVATE KEY-----', b''). \
                replace(b'\r', b'\n'). \
                replace(b'\n', b'')
        return b

    @staticmethod
    def to_string(key: Union[RSAPrivateKey, Ed25519PrivateKey], strip: bool=False, password: Optional[bytes]=None) -> str:
        return PrivateKeyHelper.to_bytes(key, strip, password).decode('utf-8')

    @staticmethod
    def to_file(key: Union[RSAPrivateKey, Ed25519PrivateKey], filename: str, strip: bool=False, password: Optional[bytes]=None):
        with open(filename, 'wb') as f:
            f.write(PrivateKeyHelper.to_bytes(key, strip, password))

    @staticmethod
    def fingerprint(key: Union[RSAPrivateKey, Ed25519PrivateKey], strip: bool=False) -> str:
        """return fingerprint for public key instead"""
        return PublicKeyHelper.fingerprint(key.public_key(), strip)

    @staticmethod
    def compare_fingerprint(key: Union[RSAPrivateKey, Ed25519PrivateKey], fingerprint: str) -> bool:
        return PublicKeyHelper.compare_fingerprint(key.public_key(), fingerprint)


class PublicKeyHelper:
    @staticmethod
    def from_bytes(key: bytes) -> Union[RSAPublicKey, Ed25519PublicKey]:
        if len(key) > 0 and key[:1] != b'-':
            key = b'-----BEGIN PUBLIC KEY-----\n' + key + b'\n-----END PUBLIC KEY-----\n'
        return load_key(key, False, None)

    @staticmethod
    def from_string(key: str) -> Union[RSAPublicKey, Ed25519PublicKey]:
        return PublicKeyHelper.from_bytes(key.encode('utf-8'))

    @staticmethod
    def from_file(filename: str) -> Union[RSAPublicKey, Ed25519PublicKey]:
        with open(filename, 'rb') as f:
            return PublicKeyHelper.from_bytes(f.read())

    @staticmethod
    def to_bytes(key: Union[RSAPublicKey, Ed25519PublicKey], strip: bool=False, ssh: bool=False) -> bytes:
        b = key.public_bytes(Encoding.OpenSSH if ssh else Encoding.PEM, PublicFormat.OpenSSH if ssh else PublicFormat.SubjectPublicKeyInfo)
        if strip:
            b = b.\
                replace(b'-----BEGIN PUBLIC KEY-----', b'').\
                replace(b'-----END PUBLIC KEY-----', b'').\
                replace(b'ssh-rsa ', b'').\
                replace(b'ssh-ed25519 ', b'').\
                replace(b'\r', b'\n').\
                replace(b'\n', b'')
        return b

    @staticmethod
    def to_string(key: Union[RSAPublicKey, Ed25519PublicKey], strip: bool=False) -> str:
        return PublicKeyHelper.to_bytes(key, strip).decode('utf-8')

    @staticmethod
    def to_file(key: Union[RSAPublicKey, Ed25519PublicKey], filename: str, strip: bool=False):
        with open(filename, 'wb') as f:
            f.write(PublicKeyHelper.to_bytes(key, strip))

    @staticmethod
    def fingerprint(key: Union[RSAPublicKey, Ed25519PublicKey], strip: bool=False) -> str:
        """matches ssh-keygen fingerprints"""

        b64 = PublicKeyHelper.to_bytes(key, True, True)
        raw = base64.b64decode(b64, validate=True)

        hasher = hashes.Hash(hashes.SHA256())
        hasher.update(raw)
        digest = hasher.finalize()
        fingerprint = base64.b64encode(digest).decode('utf-8')
        while fingerprint[-1] == '=':
            fingerprint = fingerprint[0:-1]
        if strip:
            return fingerprint
        else:
            return 'SHA256:' + fingerprint
        
    @staticmethod
    def compare_fingerprint(key: Union[RSAPublicKey, Ed25519PublicKey], fingerprint: str) -> bool:
        a = PublicKeyHelper.fingerprint(key)
        b = fingerprint
        if a.startswith("SHA256:"):
            a = a[len("SHA256:"):]
        if b.startswith("SHA256:"):
            b = b[len("SHA256:"):]
        while a[-1] == '=':
            a = a[0:-1]
        while b[-1] == '=':
            b = b[0:-1]
        return a == b
