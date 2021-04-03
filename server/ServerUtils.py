import hashlib
import hmac
import time
import json
import random
import base64
import os
import KeyDerivation

class ServerUtils:

    def __init__(self):
        self.kdf = KeyDerivation.KeyDerivation()
        self.currentVersion = "0.0.1"

    # Nonce generation from https://github.com/joestump/python-oauth2/issues/9
    # due to CVE-2013-4347 http://www.openwall.com/lists/oss-security/2013/09/12/7
    def generateNonce(self, length):
        """ Generates a random string of bytes, base64 encoded """
        if length < 1:
            return ''
        string = base64.b64encode(os.urandom(length),altchars=b'-_')
        b64len = 4 * min(length, 3)
        if length % 3 == 1:
            b64len+=2
        elif length % 3 == 2:
            b64len+=3
        return string[0:b64len].decode()

    def verifyHmac(self, key, nonce, version, _hmac):
        message = {
            "key": key,
            "nonce": nonce,
            "version": version
        }
        messageString = json.dumps(message).encode("utf-8")
        secretKey = self.kdf.deriveKey(nonce)
        hashGen = hmac.new(secretKey, messageString, hashlib.sha256)
        messageHash = hashGen.hexdigest()
        return hmac.compare_digest(messageHash, _hmac)

    def verifyVersion(self, version):
        if not version == self.currentVersion:
            return False
        return True
        
    def signResponse(self, key, nonce, version, _hmac):
        serverNonce = self.generateNonce(64)
        message = {
            "key": key,
            "nonce": nonce,
            "version": version,
            "hmac": _hmac,
            "serverNonce": serverNonce
        }
        messageString = json.dumps(message).encode("utf-8")
        secretKey = self.kdf.deriveKey(serverNonce)
        hashGen = hmac.new(secretKey, messageString, hashlib.sha256)
        messageHash = hashGen.hexdigest()
        message["serverSignature"] = messageHash
        return message