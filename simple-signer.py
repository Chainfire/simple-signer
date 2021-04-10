import sys
import os
import json
from typing import Optional, Union

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from cryptography.hazmat.primitives.serialization import load_der_private_key, load_der_public_key
from cryptography.hazmat.primitives.serialization.ssh import load_ssh_private_key, load_ssh_public_key
from cryptography.hazmat.primitives.serialization.pkcs7 import load_der_pkcs7_certificates, load_pem_pkcs7_certificates
from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
from cryptography.x509 import load_der_x509_certificate, load_pem_x509_certificate

from simplesigner import *
from simplesigner.util import minify_json

VERSION = "1.0"


def usage():
    print("Chainfire's Simple Signer :: utility version %s :: file format revision %d" % (VERSION, SimpleSigner.VERSION))
    print("")
    print("----- Signing and verifying -----")
    print("")
    print("%s <class> -sign <private-key-filename> <in-filename> <out-filename> [metadata]" % sys.argv[0])
    print("%s <class> -verify <verification> <filename>" % sys.argv[0])
    print("")
    print("Where <class> is one of:")
    print("    -json    JSON signer")
    print("    -zip     ZIP signer")
    print("    -binary  Generic binary signer")
    print("    -auto    Automatic selection")
    print("")
    print("For -sign, [metadata] is one of:")
    print("    (nothing)                No metadata")
    print("    <metadata-filename>      Path to JSON file")
    print("    <metadata-literal>       Literal JSON (beware escape characters!)")
    print("")
    print("For -verify, <verification> is one of:")
    print("    -                        Do not verify signature key")
    print("    <public-key-filename>    Path to public key file")
    print("    <private-key-filename>   Path to private key file")
    print("    <fingerprint-filename>   Path to public key fingerprint file")
    print("    <fingerprint-literal>    Literal fingerprint (beware escape characters!)")
    print("")
    print("Key files are expected to be PEM-encoded X.509 SubjectPrivate/PublicKeyInfo")
    print("(PKCS#8) for RSA or Ed25519, though PEM-encoded RSA (PKCS#1) files also")
    print("usually work. Try -convert described below if your keys don't work.")
    print("")
    print("----- Utility -----")
    print("")
    print("%s -info <private-or-public-key-filename>" % sys.argv[0])
    print("     Shows public key info (directly supported keys only)")
    print("")
    print("%s -convert -private <private-key-in-filename> <private-key-out-filename>" % sys.argv[0])
    print("%s -convert -public <private-or-public-key-in-filename> <public-key-out-filename>" % sys.argv[0])
    print("     Try to load the key from several different formats and save to PKCS#8")


def load_json_metadata(metadata: Optional[str]) -> Optional[str]:
    data = {}
    if metadata is not None:
        if os.path.isfile(metadata):
            with open(metadata, "r") as f:
                data = json.load(f)
        else:
            data = json.loads(metadata)
    data['signer-sources'] = 'https://github.com/Chainfire/simple-signer/'
    return data


def load_key(filename: str, private: bool=False, password: Optional[bytes]=None, extensive: bool=False) -> Union[RSAPrivateKey, RSAPublicKey, Ed25519PrivateKey, Ed25519PublicKey]:
    key = None

    if password is None and not extensive:
        with open(filename, 'r') as f:
            if 'ENCRYPTED' in f.readline():
                password = input("Password: ").encode('utf-8')
                if len(password) == 0:
                    password = None

    # PEM Public Key
    if not key and not private:
        try:
            key = PublicKeyHelper.from_file(filename)
        except:
            pass

    # PEM Private Key
    if not key:
        try:
            key = PrivateKeyHelper.from_file(filename, password=password)
        except:
            pass

    if extensive and not key:
        with open(filename, 'rb') as f:
            data = f.read()

        # DER Public Key
        if not key and not private:
            try:
                key = load_der_public_key(data)
            except:
                pass

        # DER Private Key
        if not key:
            try:
                key = load_der_private_key(data, password=password)
            except:
                pass

        # OpenSSH Public Key
        if not key and not private:
            try:
                key = load_ssh_public_key(data)
            except:
                pass

        # OpenSSH Private Key
        if not key:
            try:
                key = load_ssh_private_key(data, password=password)
            except:
                pass

        # PKCS#7 Certificate (Public Key)
        if not key and not private:
            certs = None
            try:
                certs = load_der_pkcs7_certificates(data)
            except:
                try:
                    certs = load_pem_pkcs7_certificates(data)
                except:
                    pass
            if certs:
                if len(certs) > 1:
                    print("Multiple certificates found, using first entry [%s]" % certs[0].subject, file=sys.stderr)
                key = certs[0].public_key()

        # PKCS#12 Certificate (Private and/or Public Key)
        if not key:
            try:
                private_key, cert, more_certs = load_key_and_certificates(data, password=password)
                if not private and cert:
                    key = cert.public_key()
                elif private:
                    key = private_key
            except:
                pass

        # X.509 Certificate
        if not key and not private:
            cert = None
            try:
                cert = load_der_x509_certificate(data)
            except:
                try:
                    cert = load_pem_x509_certificate(data)
                except:
                    pass
            if cert:
                key = cert.public_key()

    if key:
        if private and isinstance(key, RSAPrivateKey):
            return key
        if not private and isinstance(key, RSAPrivateKey):
            return key.public_key()
        elif isinstance(key, RSAPublicKey):
            return key

        if private and isinstance(key, Ed25519PrivateKey):
            return key
        if not private and isinstance(key, Ed25519PrivateKey):
            return key.public_key()
        elif isinstance(key, Ed25519PublicKey):
            return key

    raise FileException("Could not read key")


def print_sign_result(result: SimpleSigner.SignResult):
    print("SIGN OK", file=sys.stderr)
    print("")
    print("Mode: %s" % result.mode)
    print("Bytes signed: %d" % result.bytes_signed)
    print("Public key: %s" % PublicKeyHelper.to_string(result.public_key, True))
    print("Public key fingerprint: %s" % PublicKeyHelper.fingerprint(result.public_key, True))
    print("Signature: %s" % result.signature)
    print("Metadata: %s" % (minify_json(result.metadata) if result.metadata else "<none>"))


def print_verify_result(result: SimpleSigner.VerifyResult):
    if not result.public_key_verified:
        print("VERIFY PARTIAL", file=sys.stderr)
        print("")
        print("WARNING: No external public key or fingerprint passed, this does not prove authenticity! It only proves the signed part of the content has not been modified since signing, not who signed it.", file=sys.stderr)
        print("")
    else:
        print("VERIFY OK", file=sys.stderr)
        print("")

    print("Mode: %s" % result.mode)
    print("Bytes verified: %d" % result.bytes_verified)
    print("Public key: %s" % PublicKeyHelper.to_string(result.public_key, True))
    print("Public key fingerprint: %s" % PublicKeyHelper.fingerprint(result.public_key, True))
    print("Public key verified: %s" % ("Yes" if result.public_key_verified else "No"))
    print("Signature: %s" % result.signature)
    print("Metadata: %s" % (minify_json(result.metadata) if result.metadata else "<none>"))


def print_public_key_info(filename: str):
    key = load_key(filename, private=False, extensive=False)
    print("Public key: %s" % PublicKeyHelper.to_string(key, True))
    print("Public key fingerprint: %s" % PublicKeyHelper.fingerprint(key, True))


def main() -> Optional[bool]:
    # sign/verify

    signer_class = None
    do_sign = False
    do_verify = False

    if len(sys.argv) >= 2:
        if sys.argv[1] == "-json":
            signer_class = SimpleJsonSigner
        elif sys.argv[1] == "-zip":
            signer_class = SimpleZipSigner
        elif sys.argv[1] == "-binary":
            signer_class = SimpleBinarySigner
        elif sys.argv[1] == "-auto":
            signer_class = SimpleAutoSigner

    if len(sys.argv) >= 6 and sys.argv[2] == "-sign":
        do_sign = True
    elif len(sys.argv) >= 5 and sys.argv[2] == "-verify":
        do_verify = True

    if signer_class is not None and (do_sign or do_verify):
        try:
            if do_sign:
                print_sign_result(signer_class(load_key(sys.argv[3], private=True, extensive=False)).sign(sys.argv[4], sys.argv[5], load_json_metadata(sys.argv[6] if len(sys.argv) >= 7 else None)))
                return True
            elif do_verify:
                key = None
                if sys.argv[3] != '-':
                    try:
                        key = load_key(sys.argv[3], private=False, extensive=False)
                    except:
                        if os.path.isfile(sys.argv[3]):
                            with open(sys.argv[3], 'r') as f:
                                key = f.readline().strip('\n')
                        else:
                            key = sys.argv[3]
                print_verify_result(signer_class(key).verify(sys.argv[4]))
                return True
        except BaseException as e:
            if do_sign:
                print("SIGN FAIL", file=sys.stderr)
            elif do_verify:
                print("VERIFY FAIL", file=sys.stderr)
            raise e

    # info

    if len(sys.argv) >= 3 and sys.argv[1] == "-info":
        print_public_key_info(sys.argv[2])
        return True

    # convert

    if len(sys.argv) >= 5 and sys.argv[1] == "-convert":
        if sys.argv[2] == '-private':
            try:
                key = load_key(sys.argv[3], private=True, extensive=True)
                PrivateKeyHelper.to_file(key, sys.argv[4])
                print("Converted")
                return True
            except:
                try:
                    print("Could not read key, try a password ?")
                    password = input("Password: ").encode('utf-8')
                    key = load_key(sys.argv[3], private=True, extensive=True, password=password)
                    PrivateKeyHelper.to_file(key, sys.argv[4], password=password)
                    print("Converted")
                    return True
                except:
                    print("Could not read key")
                    return False
        elif sys.argv[2] == '-public':
            try:
                key = load_key(sys.argv[3], private=False, extensive=True)
                PublicKeyHelper.to_file(key, sys.argv[4])
                print("Converted")
                return True
            except:
                try:
                    print("Could not read key, try a password ?")
                    password = input("Password: ").encode('utf-8')
                    key = load_key(sys.argv[3], private=True, extensive=True, password=password)
                    PublicKeyHelper.to_file(key, sys.argv[4])
                    print("Converted")
                    return True
                except:
                    print("Could not read key")
                    return False

    return None


if __name__ == "__main__":
    ret = main()
    if ret is None:
        usage()
    elif not ret:
        exit(1)
    else:
        exit(0)
