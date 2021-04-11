from typing import Optional, Any

from .exceptions import *
from .simple_signer import SimpleSigner
from .simple_json_signer import SimpleJsonSigner
from .simple_zip_signer import SimpleZipSigner
from .simple_binary_signer import SimpleBinarySigner
from .util import KEY_ALL_TYPES


class SimpleAutoSigner(SimpleSigner):
    def __init__(self, key_or_fingerprint: Optional[KEY_ALL_TYPES]):
        super().__init__(key_or_fingerprint)
        classes = [SimpleJsonSigner, SimpleZipSigner, SimpleBinarySigner]
        self._signers = [signer_class(key_or_fingerprint) for signer_class in classes]
        self._verifiers = [signer_class(key_or_fingerprint) for signer_class in reversed(classes)]

    def mode(self) -> str:
        return "AUTO"

    def can_sign(self, infilename: str) -> bool:
        for signer in self._signers:
            if signer.can_sign(infilename):
                return True
        return False

    def can_verify(self, infilename: str) -> bool:
        for signer in self._verifiers:
            if signer.can_verify(infilename):
                return True
        return False

    def sign(self, infilename: str, outfilename: str, metadata: Optional[Any]=None) -> SimpleSigner.SignResult:
        for signer in self._signers:
            if signer.can_sign(infilename):
                return signer.sign(infilename, outfilename, metadata)
        raise InternalException("This never happens")

    def verify(self, infilename: str) -> SimpleSigner.VerifyResult:
        for signer in self._verifiers:
            if signer.can_verify(infilename):
                return signer.verify(infilename)
        raise NotSignedException()
