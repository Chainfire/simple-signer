import json
from typing import Tuple, Any, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import utils, padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .block_generators import *
from .exceptions import InternalException


def minify_json(obj: Any) -> str:
    return json.dumps(obj, indent=None, separators=(',', ':'), sort_keys=True)


def load_key(key: bytes, private: bool, password: Optional[bytes]=None):
    if private:
        return serialization.load_pem_private_key(key, password=password, backend=default_backend())
    else:
        return serialization.load_pem_public_key(key, backend=default_backend())


def sign(private_key: Union[RSAPrivateKey, Ed25519PrivateKey], blocks: Generator[bytes, None, None]) -> Tuple[int, bytes]:
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
    else:
        raise InternalException("Unknown key type")
    return count, sig


def verify(public_key: Union[RSAPublicKey, Ed25519PublicKey], blocks: Generator[bytes, None, None], signature: bytes) -> Tuple[int, bool]:
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
        else:
            raise InternalException("Unknown key type")
        return count, True
    except InvalidSignature:
        return count, False
