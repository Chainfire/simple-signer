import base64
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption, BestAvailableEncryption
from sha3 import keccak_256

from .util import load_key, KEY_PRIVATE_TYPES, KEY_PUBLIC_TYPES, is_supported_key, is_ethereum_key


"""
Helper classes for PEM-encoded RSA, Ed25519, and EC/secp256k1 keys; expected format is X.509
SubjectPrivate/PublicKeyInfo (PKCS#8, marked by -----BEGIN/END PUBLIC/PRIVATE KEY-----) though some methods will 
also accept RSA keys (PKCS#1, marked by -----BEGIN/END RSA PUBLIC/PRIVATE KEY-----) as input.

Fingerprinting uses OpenSSH format so the results match ssh-keygen output - which is used in a lot of places
online - for RSA and Ed25519 keys. EC/secp256k1 are assumed to be used Ethereum-style, and produce the address
as fingerprint. Fingerprint results for other formats (including non-secp256k1 EC) are undefined and subject
to change (as they're not officially supported).
"""


class PrivateKeyHelper:
    @staticmethod
    def from_bytes(key: bytes, password: Optional[bytes]=None) -> KEY_PRIVATE_TYPES:
        if len(key) > 0 and key[:1] != b'-':
            key = b'-----BEGIN PRIVATE KEY-----\n' + key + b'\n-----END PRIVATE KEY-----\n'
        return load_key(key, True, password)

    @staticmethod
    def from_string(key: str, password: Optional[bytes]=None) -> KEY_PRIVATE_TYPES:
        return PrivateKeyHelper.from_bytes(key.encode('utf-8'), password)

    @staticmethod
    def from_file(filename: str, password: Optional[bytes]=None) -> KEY_PRIVATE_TYPES:
        with open(filename, 'rb') as f:
            return PrivateKeyHelper.from_bytes(f.read(), password)

    @staticmethod
    def to_bytes(key: KEY_PRIVATE_TYPES, strip: bool=False, password: Optional[bytes]=None) -> bytes:
        b = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption() if password is None else BestAvailableEncryption(password))
        if password is None and strip:
            b = b. \
                replace(b'-----BEGIN PRIVATE KEY-----', b''). \
                replace(b'-----END PRIVATE KEY-----', b''). \
                replace(b'\r', b'\n'). \
                replace(b'\n', b'')
        return b

    @staticmethod
    def to_string(key: KEY_PRIVATE_TYPES, strip: bool=False, password: Optional[bytes]=None) -> str:
        return PrivateKeyHelper.to_bytes(key, strip, password).decode('utf-8')

    @staticmethod
    def to_file(key: KEY_PRIVATE_TYPES, filename: str, strip: bool=False, password: Optional[bytes]=None):
        with open(filename, 'wb') as f:
            f.write(PrivateKeyHelper.to_bytes(key, strip, password))

    @staticmethod
    def fingerprint(key: KEY_PRIVATE_TYPES, strip: bool=False) -> str:
        """return fingerprint for public key instead"""
        return PublicKeyHelper.fingerprint(key.public_key(), strip)

    @staticmethod
    def compare_fingerprint(key: KEY_PRIVATE_TYPES, fingerprint: str) -> bool:
        return PublicKeyHelper.compare_fingerprint(key.public_key(), fingerprint)


class PublicKeyHelper:
    @staticmethod
    def from_bytes(key: bytes) -> KEY_PUBLIC_TYPES:
        if len(key) > 0 and key[:1] != b'-':
            key = b'-----BEGIN PUBLIC KEY-----\n' + key + b'\n-----END PUBLIC KEY-----\n'
        return load_key(key, False, None)

    @staticmethod
    def from_string(key: str) -> KEY_PUBLIC_TYPES:
        return PublicKeyHelper.from_bytes(key.encode('utf-8'))

    @staticmethod
    def from_file(filename: str) -> KEY_PUBLIC_TYPES:
        with open(filename, 'rb') as f:
            return PublicKeyHelper.from_bytes(f.read())

    @staticmethod
    def to_bytes(key: KEY_PUBLIC_TYPES, strip: bool=False, ssh: bool=False, point: bool=False) -> bytes:
        b = key.public_bytes(Encoding.OpenSSH if ssh else (Encoding.X962 if point else Encoding.PEM), PublicFormat.OpenSSH if ssh else (PublicFormat.UncompressedPoint if point else PublicFormat.SubjectPublicKeyInfo))
        if strip and not point:
            b = b.\
                replace(b'-----BEGIN PUBLIC KEY-----', b'').\
                replace(b'-----END PUBLIC KEY-----', b'').\
                replace(b'ssh-rsa ', b'').\
                replace(b'ssh-ed25519 ', b'').\
                replace(b'\r', b'\n').\
                replace(b'\n', b'')
        return b

    @staticmethod
    def to_string(key: KEY_PUBLIC_TYPES, strip: bool=False) -> str:
        return PublicKeyHelper.to_bytes(key, strip).decode('utf-8')

    @staticmethod
    def to_file(key: KEY_PUBLIC_TYPES, filename: str, strip: bool=False):
        with open(filename, 'wb') as f:
            f.write(PublicKeyHelper.to_bytes(key, strip))

    @staticmethod
    def fingerprint(key: KEY_PUBLIC_TYPES, strip: bool=False) -> str:
        """matches ssh-keygen fingerprints for RSA and Ed25519, Ethereum address for secp256k1, undefined for others"""

        is_address = False

        if is_ethereum_key(key):
            is_address = True
            b64 = PublicKeyHelper.to_bytes(key, True, False, True)
        elif is_supported_key(key):
            b64 = PublicKeyHelper.to_bytes(key, True, True)
        else:
            try:
                b64 = PublicKeyHelper.to_bytes(key, True, True)
            except:
                b64 = PublicKeyHelper.to_bytes(key, True, False)

        if not is_address:
            prefix = 'SHA256:'
            raw = base64.b64decode(b64, validate=True)

            hasher = hashes.Hash(hashes.SHA256())
            hasher.update(raw)
            digest = hasher.finalize()
            fingerprint = base64.b64encode(digest).decode('utf-8')
            while fingerprint[-1] == '=':
                fingerprint = fingerprint[0:-1]
        else:
            prefix = 'Keccak256:'
            raw = b64[1:]

            hasher = keccak_256()
            hasher.update(raw)
            address = hasher.hexdigest()[-40:]

            hasher = keccak_256()
            hasher.update(address.encode('utf-8'))
            hashed = hasher.hexdigest().lower()

            fingerprint = "0x"
            for i in range(0, 40):
                if hashed[i] in '89abcdef':
                    fingerprint += address[i].upper()
                else:
                    fingerprint += address[i].lower()

        if strip:
            return fingerprint
        else:
            return prefix + fingerprint

    @staticmethod
    def compare_fingerprint(key: KEY_PUBLIC_TYPES, fingerprint: str) -> bool:
        a = PublicKeyHelper.fingerprint(key)
        b = fingerprint
        if a.startswith("SHA256:"):
            a = a[len("SHA256:"):]
        if b.startswith("SHA256:"):
            b = b[len("SHA256:"):]
        if a.startswith("Keccak256:"):
            a = a[len("Keccak256:"):]
        if b.startswith("Keccak256:"):
            b = b[len("Keccak256:"):]
        if a.startswith('0x'):
            a = a.lower()
        if b.startswith('0x'):
            b = b.lower()
        while a[-1] == '=':
            a = a[0:-1]
        while b[-1] == '=':
            b = b[0:-1]
        return a == b
