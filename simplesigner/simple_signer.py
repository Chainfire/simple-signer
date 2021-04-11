from typing import Optional, Any

from .exceptions import *
from .util import KEY_PRIVATE_TYPES, KEY_PUBLIC_TYPES, KEY_ALL_TYPES, is_private_key, is_public_key


class SimpleSigner:
    VERSION = 2
    MAGIC = 'CFSS'

    class SignResult:
        def __init__(self, mode: str, bytes_signed: int, signature: str, public_key: KEY_PUBLIC_TYPES, metadata: Optional[Any]):
            self.mode = mode
            """Signer mode"""

            self.bytes_signed = bytes_signed
            """Number of bytes processed in signature"""

            self.signature = signature
            """Base64 of produced signature"""

            self.public_key = public_key
            """Public key that can be used to verify the signature"""

            self.metadata = metadata
            """Metadata included"""

    class VerifyResult:
        def __init__(self, mode: str, bytes_verified: int, signature: str, public_key: KEY_PUBLIC_TYPES, public_key_verified: bool, metadata: Optional[Any]):
            self.mode = mode
            """Signer mode"""

            self.bytes_verified = bytes_verified
            """Number of bytes processed in signature verification"""

            self.signature = signature
            """Base64 of verified signature"""

            self.public_key = public_key
            """Public key used to verify signature"""

            self.public_key_verified = public_key_verified
            """Whether the public key is verified. If False, the key from the signature itself was used to verify,
            which only proves the content of the checked bytes have not been modified since signing, this does not
            prove authenticity as anyone could re-sign the file. If True, the public key from the signature matches
            the public key provided to the SimpleSigner constructor - if that public key has been retrieved from the
            original signer through a secondary route from the supplied file, this proves authenticity (provided the
            original signer's private key has not been leaked and RSA/Ed25519 have not been cracked)"""

            self.metadata = metadata
            """Metadata included"""

    def __init__(self, key_or_fingerprint: Optional[KEY_ALL_TYPES]):
        """
        An xxxPrivateKey is required to sign. To verify properly an xxxPublicKey or fingerprint str needs to be provided;
        if omitted, the public key stored in the signature is used for verification, which only proves the checked
        bytes have not been modified since signing, it does not prove the authenticity of the whole.

        If an xxxPrivateKey is provided, it's public part is also loaded automatically, so passing an xxxPrivateKey
        allows you to both sign and properly verify.

        :param key_or_fingerprint: RSAPrivateKey, Ed25519PrivateKey, EllipticCurvePrivateKey, RSAPublicKey, Ed25519PublicKey, EllipticCurvePublicKey, str (fingerprint), or None
        """
        if key_or_fingerprint is None:
            self._private_key = None  # type: Optional[KEY_PRIVATE_TYPES]
            self._public_key = None  # type: Optional[KEY_PUBLIC_TYPES]
            self._fingerprint = None  # type: Optional[str]
        elif isinstance(key_or_fingerprint, str):
            self._private_key = None
            self._public_key = None
            self._fingerprint = key_or_fingerprint
        elif is_private_key(key_or_fingerprint):
            self._private_key = key_or_fingerprint
            self._public_key = key_or_fingerprint.public_key()
            self._fingerprint = None
        elif is_public_key(key_or_fingerprint):
            self._private_key = None
            self._public_key = key_or_fingerprint
            self._fingerprint = None

    def _check_private_key(self):
        if self._private_key is None:
            raise PrivateKeyRequiredException()

    def _check_public_key(self):
        if self._public_key is None:
            raise PublicKeyRequiredException()

    def mode(self) -> str:
        raise NotImplementedError()

    def can_sign(self, infilename: str) -> bool:
        raise NotImplementedError()

    def can_verify(self, infilename: str) -> bool:
        raise NotImplementedError()

    def sign(self, infilename: str, outfilename: str, metadata: Optional[Any]=None) -> SignResult:
        """Sign infilename with private key and save to outfilename, the optional metadata should be json serializable.
        Throws an exception unless successful."""
        raise NotImplementedError()

    def verify(self, infilename: str) -> VerifyResult:
        """Verify infilename with public key (if set, otherwise it uses the key stored next to the signature). Throws
        an exception unless successful."""
        raise NotImplementedError()
