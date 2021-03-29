import json
import base64
import zipfile
from typing import Optional, Any, Generator

from .exceptions import *
from .key_helpers import PublicKeyHelper
from .block_generators import BytesBlockGenerator, ChainedBlockGenerator
from .util import sign, verify, minify_json
from .simple_signer import SimpleSigner


class SimpleZipSigner(SimpleSigner):
    """
    Adds/verifies "signature.json" in zip file:

    "signature": {
        "metadata": <metadata object or null>,
        "key": <public key in base64>,
        "magic": "CFSS",
        "version": "1",
        "signature": <signature in base64>
    }

    Signing:
    - Input zip file entries are sorted
    - Signature block is added with (magic, version, signature) set to None, but (metadata, key) set
    - Resulting json data is minified (with key-sorting)
    - Signature is calculated based on sorted zip file entries' content + that minified json (which includes the metadata and public key)
    - (magic, version, signature) are added to signature block
    - Zip file is copied
    - signature.json is added to copied zip file

    Verifying:
    - Input zip file entries are sorted, excluding signature.json
    - Signature json's (magic, version, signature) are set to None
    - Resulting json data is minified (with key-sorting)
    - Signature is verified based on sorted zip file entries' content + that minified json
    """

    class ZipEntryBlockGenerator():
        def __init__(self, zip: zipfile.ZipFile, filename: str):
            self._zip = zip
            self._filename = filename

        def generator(self) -> Generator[bytes, None, None]:
            with self._zip.open(self._filename) as f:
                while True:
                    block = f.read(64 * 1024)
                    if not block:
                        break
                    yield block

    def mode(self) -> str:
        return "ZIP"

    def can_sign(self, infilename: str) -> bool:
        try:
            with zipfile.ZipFile(infilename, 'r', zipfile.ZIP_STORED, True):
                return True
        except:
            return False

    def can_verify(self, infilename: str) -> bool:
        return self.can_sign(infilename)

    def sign(self, infilename: str, outfilename: str, metadata: Optional[Any] = None) -> SimpleSigner.SignResult:
        self._check_private_key()
        self._check_public_key()
        with zipfile.ZipFile(infilename, 'r', zipfile.ZIP_STORED, True) as zip:
            if len(zip.namelist()) == 0:
                raise EmptyFileException()
            if 'signature.json' in zip.namelist():
                raise AlreadySignedException("Input already signed")

            generators = []
            uncompressed_size = 0
            for info in sorted(zip.infolist(), key=lambda x: x.filename):
                if not info.is_dir():
                    generators.append(self.ZipEntryBlockGenerator(zip, info.filename).generator())
                    uncompressed_size += info.file_size

            js = {
                'metadata': metadata,
                'key': PublicKeyHelper.to_string(self._public_key, True),
                'magic': None,
                'version': None,
                'signature': None
            }
            memory = minify_json(js).encode('utf-8')
            generators.append(BytesBlockGenerator(memory).generator())
            count, signature = sign(self._private_key, ChainedBlockGenerator(generators).generator())
            if count != uncompressed_size + len(memory):
                raise InternalException("count != len(zipentries) + len(memory)")
            b64 = base64.b64encode(signature).decode('utf-8')
            js.update({
                'magic': self.MAGIC,
                'version': self.VERSION,
                'signature': b64,
            })

        with open(infilename, 'rb') as fin:
            with open(outfilename, 'wb') as fout:
                while True:
                    block = fin.read(64 * 1024)
                    if not block:
                        break
                    fout.write(block)

        with zipfile.ZipFile(outfilename, 'a', zipfile.ZIP_STORED, True) as zip:
            with zip.open('signature.json', 'w') as f:
                f.write(json.dumps(js, indent=4).encode('utf-8'))

        return SimpleSigner.SignResult(self.mode(), count, b64, self._public_key, metadata)

    def verify(self, infilename: str) -> SimpleSigner.VerifyResult:
        with zipfile.ZipFile(infilename, 'r', zipfile.ZIP_STORED, True) as zip:
            if 'signature.json' not in zip.namelist():
                raise NotSignedException("Input file not signed")

            if self._public_key is None:
                public_key = None
                public_key_str = None
            else:
                public_key = self._public_key
                public_key_str = PublicKeyHelper.to_string(self._public_key, True)

            with zip.open('signature.json', 'r') as f:
                js = json.load(f)
            if not js or 'signature' not in js:
                raise NotSignedException("Input file not signed")
            if 'magic' not in js or js['magic'] != self.MAGIC or 'version' not in js:
                raise NotSignedBySimpleSignerException()
            if js['version'] > self.VERSION:
                raise SignedByNewerSimpleSignerVersionException()

            if not public_key:
                public_key_str = js['key']
                public_key = PublicKeyHelper.from_string(public_key_str)
                if self._fingerprint and not PublicKeyHelper.compare_fingerprint(public_key, self._fingerprint):
                    raise PublicKeyMismatchException("Provided public key fingerprint does not match public key in file")
            else:
                if js['key'] != public_key_str:
                    raise PublicKeyMismatchException("Provided public key does not match public key in file")

            provided_signature_b64 = js['signature']
            provided_signature = base64.b64decode(provided_signature_b64.encode('utf-8'), validate=True)
            js.update({
                'magic': None,
                'version': None,
                'signature': None
            })
            metadata = None
            if 'metadata' in js and js['metadata']:
                metadata = js['metadata']

            generators = []
            uncompressed_size = 0
            for info in sorted(zip.infolist(), key=lambda x: x.filename):
                if not info.is_dir() and info.filename != 'signature.json':
                    generators.append(self.ZipEntryBlockGenerator(zip, info.filename).generator())
                    uncompressed_size += info.file_size

            memory = minify_json(js).encode('utf-8')
            generators.append(BytesBlockGenerator(memory).generator())
            count, valid = verify(public_key, ChainedBlockGenerator(generators).generator(), provided_signature)
            if count != uncompressed_size + len(memory):
                raise InternalException("count != len(zipentries) + len(memory)")
            if not valid:
                raise SignatureVerificationFailed()
            return SimpleSigner.VerifyResult(self.mode(), count, provided_signature_b64, PublicKeyHelper.from_string(public_key_str), self._public_key is not None or self._fingerprint is not None, metadata)
