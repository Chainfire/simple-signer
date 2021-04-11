import json
from typing import Tuple, Any, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import utils, padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey, ECDSA

from .block_generators import *
from .exceptions import InternalException


KEY_PRIVATE_TYPES = Union[RSAPrivateKey, Ed25519PrivateKey, EllipticCurvePrivateKey]
KEY_PUBLIC_TYPES = Union[RSAPublicKey, Ed25519PublicKey, EllipticCurvePublicKey]
KEY_ALL_TYPES = Union[RSAPrivateKey, Ed25519PrivateKey, EllipticCurvePrivateKey, RSAPublicKey, Ed25519PublicKey, EllipticCurvePublicKey]


def check_union(obj: Any, union: Any):
    for t in union.__args__:
        if isinstance(obj, t):
            return True
    return False


def is_supported_key(obj: Any):
    return check_union(obj, KEY_ALL_TYPES)


def is_private_key(obj: Any):
    return check_union(obj, KEY_PRIVATE_TYPES)


def is_public_key(obj: Any):
    return check_union(obj, KEY_PUBLIC_TYPES)


def is_ethereum_key(obj: Any):
    return (isinstance(obj, EllipticCurvePrivateKey) or isinstance(obj, EllipticCurvePublicKey)) and obj.curve.name == 'secp256k1'


def minify_json(obj: Any) -> str:
    return json.dumps(obj, indent=None, separators=(',', ':'), sort_keys=True)


def load_key(key: bytes, private: bool, password: Optional[bytes]=None):
    if private:
        return serialization.load_pem_private_key(key, password=password, backend=default_backend())
    else:
        return serialization.load_pem_public_key(key, backend=default_backend())


def print_digest(digest: bytes):
    p = ""
    for b in digest:
        p += "%02x" % b
    print(p)


def sign(private_key: KEY_PRIVATE_TYPES, blocks: Generator[bytes, None, None]) -> Tuple[int, bytes]:
    chosen_hash = hashes.SHA256()
    hasher = hashes.Hash(chosen_hash)
    count = 0
    for block in blocks:
        count += len(block)
        hasher.update(block)
    digest = hasher.finalize()
    if isinstance(private_key, RSAPrivateKey):
        sig = private_key.sign(
            digest,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            utils.Prehashed(chosen_hash)
        )
    elif isinstance(private_key, Ed25519PrivateKey):
        sig = private_key.sign(digest)
    elif isinstance(private_key, EllipticCurvePrivateKey):
        sig = private_key.sign(
            digest,
            ECDSA(utils.Prehashed(chosen_hash))
        )
    else:
        raise InternalException("Unknown key type")
    return count, sig


def verify(public_key: KEY_PUBLIC_TYPES, blocks: Generator[bytes, None, None], signature: bytes) -> Tuple[int, bool]:
    count = 0
    try:
        chosen_hash = hashes.SHA256()
        hasher = hashes.Hash(chosen_hash)
        count = 0
        for block in blocks:
            count += len(block)
            hasher.update(block)
        digest = hasher.finalize()
        if isinstance(public_key, RSAPublicKey):
            public_key.verify(
                signature,
                digest,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                utils.Prehashed(chosen_hash)
            )
        elif isinstance(public_key, Ed25519PublicKey):
            public_key.verify(signature, digest)
        elif isinstance(public_key, EllipticCurvePublicKey):
            public_key.verify(
                signature,
                digest,
                ECDSA(utils.Prehashed(chosen_hash))
            )
        else:
            raise InternalException("Unknown key type")
        return count, True
    except InvalidSignature:
        return count, False
