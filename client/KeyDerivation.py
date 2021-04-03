from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512
import os

class KeyDerivation:

    def __init__(self):
        self.salt = b'\xb2\x95\xe7\x0b\x98\xba8c8,\x8d\x8a\x00\xc1\xa4p'
        self.keyLength = 32
        self.rounds = 10

    def deriveKey(self, nonce):
        password = bytes(nonce, "utf-8")
        key = PBKDF2(password, self.salt, 32, count=self.rounds)
        return key