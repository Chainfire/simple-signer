import json
import base64
from typing import Optional, Any

from .exceptions import *
from .key_helpers import PublicKeyHelper
from .block_generators import BytesBlockGenerator
from .util import sign, verify, minify_json
from .simple_signer import SimpleSigner


class SimpleJsonSigner(SimpleSigner):
    """
    Adds/verifies "signature" object on root json object:

    "signature": {
        "metadata": <metadata object or null>,
        "key": <public key in base64>,
        "magic": "CFSS",
        "version": "1",
        "signature": <signature in base64>
    }

    Signing:
    - Input file is read using python's json package
    - Signature block is added with (magic, version, signature) set to None, but (metadata, key) set
    - Resulting json data is minified (with key-sorting)
    - Signature is calculated based on that minified json (which includes the metadata and public key)
    - (magic, version, signature) are added to signature block
    - Output file is written using python's json package in pretty print mode

    Verifying:
    - Input file is read using python's json package
    - Signature block's (magic, version, signature) are set to None
    - Resulting json data is minified (with key-sorting)
    - Signature is verified based on that minified json
    """

    def mode(self) -> str:
        return "JSON"

    def can_sign(self, infilename: str) -> bool:
        try:
            with open(infilename, 'r') as f:
                js = f.read()
            json.loads(js)
            return True
        except:
            return False

    def can_verify(self, infilename: str) -> bool:
        return self.can_sign(infilename)

    def sign(self, infilename: str, outfilename: str, metadata: Optional[Any] = None) -> SimpleSigner.SignResult:
        self._check_private_key()
        self._check_public_key()
        with open(infilename, 'r') as f:
            js = f.read()

        public_key_str = PublicKeyHelper.to_string(self._public_key, True)
        js = json.loads(js)
        if not js:
            raise EmptyFileException()
        if 'signature' in js:
            raise AlreadySignedException("Input already signed")
        js['signature'] = {
            'metadata': metadata,
            'key': public_key_str,
            'magic': None,
            'version': None,
            'signature': None
        }
        memory = minify_json(js).encode('utf-8')
        count, signature = sign(self._private_key, BytesBlockGenerator(memory).generator())
        if count != len(memory):
            raise InternalException("count != len(memory)")
        b64 = base64.b64encode(signature).decode('utf-8')
        js['signature'].update({
            'magic': self.MAGIC,
            'version': self.VERSION,
            'signature': b64,
        })

        with open(outfilename, 'w') as f:
            f.write(json.dumps(js, indent=4))
        return SimpleSigner.SignResult(self.mode(), count, b64, self._public_key, metadata)

    def verify(self, infilename: str) -> SimpleSigner.VerifyResult:
        if self._public_key is None:
            public_key = None
            public_key_str = None
        else:
            public_key = self._public_key
            public_key_str = PublicKeyHelper.to_string(self._public_key, True)

        with open(infilename, 'r') as f:
            js = json.load(f)
        if not js or 'signature' not in js or 'signature' not in js['signature']:
            raise NotSignedException("Input file not signed")
        if 'magic' not in js['signature'] or js['signature']['magic'] != self.MAGIC or 'version' not in js['signature']:
            raise NotSignedBySimpleSignerException()
        if js['signature']['version'] > self.VERSION:
            raise SignedByNewerSimpleSignerVersionException()

        if not public_key:
            public_key_str = js['signature']['key']
            public_key = PublicKeyHelper.from_string(public_key_str)
            if self._fingerprint and not PublicKeyHelper.compare_fingerprint(public_key, self._fingerprint):
                raise PublicKeyMismatchException("Provided public key fingerprint does not match public key in file")
        else:
            if js['signature']['key'] != public_key_str:
                raise PublicKeyMismatchException("Provided public key does not match public key in file")

        provided_signature_b64 = js['signature']['signature']
        provided_signature = base64.b64decode(provided_signature_b64.encode('utf-8'), validate=True)
        js['signature'].update({
            'magic': None,
            'version': None,
            'signature': None
        })
        metadata = None
        if 'metadata' in js['signature'] and js['signature']['metadata']:
            metadata = js['signature']['metadata']

        memory = minify_json(js).encode('utf-8')
        count, valid = verify(public_key, BytesBlockGenerator(memory).generator(), provided_signature)
        if count != len(memory):
            raise InternalException("count != len(memory)")
        if not valid:
            raise SignatureVerificationFailed()
        return SimpleSigner.VerifyResult(self.mode(), count, provided_signature_b64, PublicKeyHelper.from_string(public_key_str), self._public_key is not None or self._fingerprint is not None, metadata)
