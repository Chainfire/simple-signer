# Simple Signer

I've recently had the need to digitally sign files in specific ways.
No easy solution seemed to exist for my exact needs. So I did the
very best thing one can do in the world of encryption: I rolled my
own.

*Simple Signer* is a small tool (and module) to sign files with
RSA or Ed25519 private keys, and verify them with the public keys
or a fingerprint thereof.

JSON metadata can be added to the signature and is returned on
verification. The tool uses different signature formats based on
file type.

The `-sign` and `-verify` command line options work with PEM-encoded
PKCS#8 keys (though PEM PKCS#1 RSA keys might also work out-of-the-box),
but a `-convert` option is provided that can read many formats,
so most of you won't have to spend hours Googling on the exactly
right OpenSSL commands to convert your keys. Password-protected
private keys are supported.

## License

This code is released under the [MIT license](./LICENSE).

## Disclaimer

I wrote this. Mind the dragons.

## Magic

File format magic bytes is "CFSS"

## Requirements

This requires recent a OpenSSL and Python 3.x.

I only needed to pip `cryptography` for the main code and `bcrypt` for 
password support after that. A `requirements.txt` is included based on
a fresh a virtualenv I tested the tool with.

`pip install -r requirements`

## Signatures

The tool signs different files in different ways, as per my requirements.
Currently three backends exist:

- JSON
- ZIP
- BINARY (generic)

An automatic backend also exists which attempts to be smart in picking
which one to use.

The public component of the key used to sign, as well as the
user-provided metadata, is included in the data hashed and verified. This
way authenticity of the data can be verified using only the fingerprint of
the original public key, which (particularly in the case of RSA keys) is a
lot less data.

A short description of the backends follows, more complete documentation
is in their source files.

Note that the final signing and verification code comes straight from
the `cryptography` docs, I assume they know what they're doing.

### JSON

The JSON signer puts a `signature` object in the JSON root. So obviously this
doesn't work if the JSON root is an array or a primitive.

Signing and verification is based on content; whitespace is ignored.

IMPORTANT: The entire JSON file is currently read by Python's `json`
module, converted to Python objects, modified, then written back out to
the output file. This means your signed JSON will be subject to the quirks
of the `json` module. While this is usually not an issue, conversion errors
*can* happen. Pay particular attention to your output files if you're using
floats.

### ZIP

The ZIP signer places a `signature.json` file in the archive root, containing
the same as the `signature` object does in a signed JSON file.

This is done for visibility and being easier to parse for third party tools.
You can use the BINARY signer on ZIP files instead if so inclined.

Signing and verification is based on the contents of the files inside the ZIP
archive, the structure of the ZIP file itself as well as entry attributes are
ignored.

Additionally, ZIP files tend to store their information twice (both near the
file contents and in the central directory) and this has been the cause of
several exploits through the years. Python's `zipfile` module is used for
reading and writing the ZIP files, so this tool is beholden to quirks of
that implementation.

Depending on your purposes, it may be important for you to guard against
such manipulations, in which case you should use the BINARY signer. This may
reduce compatibility with some tools reading ZIP files, but I have not
encountered this in testing.

### BINARY

The BINARY signer appends a (binary) signature structure to the end of the
file.

For many - but not all - file formats this is perfectly safe, programs reading
the files will generally just ignore it. I use this regularly for images.   

Signing and verification is based on the entire file up to the signature, and
the signature must be located at the end of the file.

### AUTO

The automatic signer tries to detect the file type and pick the right signer
for you.

For signing, it tests in this order:

JSON, ZIP, BINARY

For verification, it tests in reverse order:

BINARY, ZIP, JSON

In a controlled environment, it is advised to *specify* which backend to use
if you know beforehand.
  
## Usage

Run `simple-signer.py` for the full command structure.

As stated in the introduction, both RSA and Ed25519 keys are supported. Be
sure to use a responsible number of bits for your keys. Also see my note
about quantum computing below.

### Converting keys

If you have your private and public keys at the ready, with the jungle of
key formats in existence today, they may be in the wrong format. This tool
expects PEM encoded PKCS#8 keys for signing/verification.

`simple-signer.py` provides a `-convert` option, which takes keys in
many formats and outputs the correct format:

```
simple-signer.py -convert -private <in-filename> <out-filename>
simple-signer.py -convert -public <in-filename> <out-filename>
```
 
### Signing

To sign you need the *private* key:

`simple-signer.py <class> -sign <private-key-filename> <in-filename> <out-filename> [metadata]`

Where `<class>` is `-auto`, `-json`, `-zip`, or `-binary` to select the
signing backend.

`[metadata]` is optional, and can point to either a JSON file or be a
literal string (beware escape characters).

If signing succeeds, the output will also show you the public key fingerprint
you can use elsewhere. Note that these fingerprints are made to match those
`ssh-keygen` produces. You can also dump the fingerprint without signing
anything by using the `-info` option.

### Verification

To verify properly you need either the *private* key, the *public* key, or the
public key *fingerprint*.

Verification will run without any of these provided, but it will use the 
public key embedded in the signature. While this proves the signed bytes have
not been modified since the file was signed, it doesn't prove *who* signed
them.

`simple-signer.py <class> -verify <verification> <filename>`

Where `<class>` is `-auto`, `-json`, `-zip`, or `-binary` to select the
signing backend, and `<verification>` is a *private* key, *public*
key, or *fingerprint* filename; a *fingerprint* literal (beware escape
characters), or a *-* to use the key embedded in the signature.

If verification success, the output will also show you the metadata passed
at signing.

Ideally, the verifying user would retrieve the correct public key or
fingerprint through a separate channel from the file; such as a key-server,
text message, from a website or public account known to be under the author's
control, etc. 

### Module usage

Just copy/paste the `simplesigner` directory to your project and
import it. The cli tool `simple-signer.py` is a little more complicated
than most library usage would be.

I assume most users in that case would simply want to *verify* a
signature, which in its most basic form would like something like
this:

```
from simplesigner import SimpleAutoSigner, PublicKeyHelper

def verify_file_with_public_key(public_key_filename: str, verify_filename: str) -> bool:
    try:
        SimpleAutoSigner(PublicKeyHelper.from_file(filename)).verify(verify_filename)
        return True
    except:
        return False

def verify_file_with_fingerprint(fingerprint: str, verify_filename: str) -> bool:
    try:
        SimpleAutoSigner(fingerprint).verify(verify_filename)
        return True
    except:
        return False
```

Note that these example functions would return `False` if an internal error
occurred, one of the files is missing, the keys can't be parsed, etc. But
when it returns `True`, things are really good. The basic guarantee is that
`.verify` will always throw an exception unless the content is verified.

If you want to catch specific exceptions, you'd go for
`PublicKeyMismatchException` (which tells you the public key or fingerprint
you provided to the constructor does not match the one used to sign the file),
and `SignatureVerificationFailed` (which tells you the public key or
fingerprint matched - if you provided one - but the content does not) from
`simplesigner.exceptions`. 

## Quantum computing

Both RSA and Ed25519 based signatures will ultimately be vulnerable to
quantum computing attacks. To the best of my knowledge, an RSA key of
comparable classical security to an Ed25519 one (say 3072 vs 256 bits)
should hold up slightly longer; but once quantum computing is at the point
it can take down Ed25519, it seems likely RSA will follow quite quickly.
Ed25519 prevents a few other attacks that RSA is vulnerable to, and
its keys are significantly smaller. Which is to the most benefit to you
is for you to decide.

How long will it take for RSA-7680 or Ed25519-384 to be broken to the
point that anyone with USD $100K in the bank can do it? It may be as
little as half a decade, or it could be a factor of that. Predicting
the future is hard.

If using fingerprint-based verification, SHA256 being broken would also
be a possible attack vector.

There's not really a good standardized (and battle-tested) post-quantum
digital signature available at this time, otherwise I would prefer to 
use that.

Using only fingerprints of the public key rather than the public key in
full as is done in some systems can keep things significantly safer, but
does not fit the use case I'm building this for - the public key needs
to be public anyway.
