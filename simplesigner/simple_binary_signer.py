import json
import base64
from io import SEEK_END
from typing import Optional, Any

from .exceptions import *
from .key_helpers import PublicKeyHelper
from .block_generators import FileBlockGenerator, BytesBlockGenerator, ChainedBlockGenerator
from .util import sign, verify, minify_json
from .simple_signer import SimpleSigner


class SimpleBinarySigner(SimpleSigner):
    """
    Append/verifies signature to binary file:

    Format:
      <original binary data>
      <metadata as minified json (with key-sorting)>
      <base64 public key>
    ---- hashing up to here ----
      <binary signature>
      <4-byte big-endian metadata length>
      <4-byte big-endian ASCII public key length>
      <4-byte big-endian signature length>
      <4-byte big-endian footer length including magic and version number>
      <4-byte big-endian version number>
      "CFSS" magic

    """

    def mode(self) -> str:
        return "BINARY"

    def _is_signed_file(self, filename: str):
        with open(filename, 'rb') as f:
            f.seek(-4, SEEK_END)
            signed = f.read(4) == self.MAGIC.encode('utf-8')
            if signed:
                f.seek(-8, SEEK_END)
                if int.from_bytes(f.read(4), byteorder='big', signed=False) > self.VERSION:
                    raise SignedByNewerSimpleSignerVersionException()
            return signed

    def can_sign(self, infilename: str) -> bool:
        return True

    def can_verify(self, infilename: str) -> bool:
        return self._is_signed_file(infilename)

    def sign(self, infilename: str, outfilename: str, metadata: Optional[Any] = None) -> SimpleSigner.SignResult:
        self._check_private_key()
        self._check_public_key()

        if self._is_signed_file(infilename):
            raise AlreadySignedException("Input file already signed")

        public_key_bytes = PublicKeyHelper.to_bytes(self._public_key, True)

        metadata_bytes = None if not metadata else minify_json(metadata).encode('utf-8')
        metadata_bytes_length = 0 if not metadata else len(metadata_bytes)

        generators = []
        file_blocks = FileBlockGenerator(infilename)
        generators.append(file_blocks.generator())
        if metadata_bytes is not None:
            generators.append(BytesBlockGenerator(metadata_bytes).generator())
        generators.append(BytesBlockGenerator(public_key_bytes).generator())

        count, signature = sign(self._private_key, ChainedBlockGenerator(generators).generator())
        b64 = base64.b64encode(signature).decode('utf-8')

        with open(outfilename, 'wb') as f:
            for block in file_blocks.generator():
                f.write(block)
            if metadata:
                f.write(metadata_bytes)
            f.write(public_key_bytes)
            f.write(signature)
            l = metadata_bytes_length
            f.write(l.to_bytes(4, byteorder='big', signed=False))
            l = len(public_key_bytes)
            f.write(l.to_bytes(4, byteorder='big', signed=False))
            l = len(signature)
            f.write(l.to_bytes(4, byteorder='big', signed=False))
            l = 24 + metadata_bytes_length + len(public_key_bytes) + len(signature)
            f.write(l.to_bytes(4, byteorder='big', signed=False))
            f.write(self.VERSION.to_bytes(4, byteorder='big', signed=False))
            f.write(self.MAGIC.encode('utf-8'))

            if f.tell() != count + l - metadata_bytes_length - len(public_key_bytes):
                raise InternalException("tell() != count + footer_length - metadata_length - public_key_length")

            return SimpleSigner.SignResult(self.mode(), count, b64, self._public_key, metadata)

    def verify(self, infilename: str) -> SimpleSigner.VerifyResult:
        if not self._is_signed_file(infilename):
            raise NotSignedException("Input file not signed")

        if self._public_key is None:
            public_key = None
            public_key_str = None
        else:
            public_key = self._public_key
            public_key_str = PublicKeyHelper.to_string(self._public_key, True)

        with open(infilename, 'rb') as f:
            f.seek(0, SEEK_END)
            total_length = f.tell()
            f.seek(-12, SEEK_END)
            footer_length = int.from_bytes(f.read(4), byteorder='big', signed=False)
            binary_length = total_length - footer_length

            f.seek(-24, SEEK_END)

            metadata_length = int.from_bytes(f.read(4), byteorder='big', signed=False)
            public_key_length = int.from_bytes(f.read(4), byteorder='big', signed=False)
            signature_length = int.from_bytes(f.read(4), byteorder='big', signed=False)

            f.seek(-24 - signature_length - public_key_length - metadata_length, SEEK_END)

            metadata = None
            if metadata_length:
                metadata = json.loads(f.read(metadata_length).decode('utf-8'))

            provided_key = f.read(public_key_length).decode('utf-8')
            if not public_key:
                public_key_str = provided_key
                public_key = PublicKeyHelper.from_string(public_key_str)
                if self._fingerprint and not PublicKeyHelper.compare_fingerprint(public_key, self._fingerprint):
                    raise PublicKeyMismatchException("Provided public key fingerprint does not match public key in file")
            else:
                if provided_key != public_key_str:
                    raise PublicKeyMismatchException("Provided public key does not match public key in file")

            provided_signature = f.read(signature_length)
            provided_signature_b64 = base64.b64encode(provided_signature).decode('utf-8')

            count, valid = verify(public_key, FileBlockGenerator(infilename, 0, binary_length + metadata_length + public_key_length).generator(), provided_signature)
            if count != binary_length + metadata_length + public_key_length:
                raise InternalException("count != binary_length + metadata_length + public_key_length")
            return SimpleSigner.VerifyResult(self.mode(), count, provided_signature_b64, PublicKeyHelper.from_string(public_key_str), self._public_key is not None or self._fingerprint is not None, metadata)
