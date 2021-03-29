class SimpleSignerException(RuntimeError):
    pass

class InternalException(SimpleSignerException):
    pass

class FileException(SimpleSignerException):
    pass

class AlreadySignedException(FileException):
    pass

class NotSignedException(FileException):
    pass

class NotSignedBySimpleSignerException(FileException):
    pass

class SignedByNewerSimpleSignerVersionException(FileException):
    pass

class EmptyFileException(FileException):
    pass

class KeyException(SimpleSignerException):
    pass

class PrivateKeyRequiredException(KeyException):
    pass

class PublicKeyRequiredException(KeyException):
    pass

class PublicKeyMismatchException(KeyException):
    pass

class SignatureVerificationFailed(SimpleSignerException):
    pass

