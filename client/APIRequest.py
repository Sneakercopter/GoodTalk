import requests
import random
import json
import hashlib
import hmac
import base64
import os
from client import KeyDerivation

class APIRequest:

    def __init__(self, apiEndpoint):
        self.kdf = KeyDerivation.KeyDerivation()
        self.session = requests.session()
        self.currentVersion = "0.0.1"
        self.apiEndpoint = apiEndpoint

    def generateHmac(self, messageString, nonce):
        secretKey = self.kdf.deriveKey(nonce)
        hashGen = hmac.new(secretKey, messageString, hashlib.sha256)
        messageHash = hashGen.hexdigest()
        return messageHash

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

    # Here you would parse all error codes and respond appropriately. We are not running
    # any actual software, so we just print the error
    def parseErrorResponse(self, resp):
        try:
            resp = resp.json()
            errorCode = resp["error"]
            if errorCode == "key_invalid":
                print("Error: Invalid key")
            elif errorCode == "version_not_allowed":
                print("Error: Version out of date")
            else:
                print("Error: Undocumented")
        except Exception:
            print("Error: Invalid server response")

    # Fires the actual JSON request to the API endpoint and 
    def sendApiRequest(self, endpoint, jsonData):
        r = self.session.post(endpoint, json=jsonData)
        print(r.text)
        if r.status_code != 200:
            self.parseErrorResponse(r)
            return None
        return r.json()

    # Similar to how the server verifies our message integrity, we also verify the response. We want to ensure that the
    # response we get was really sent by the server and with it's integrity intact.
    def verifyServerResponse(self, message, response):
        if message["nonce"] != response["nonce"] or message["hmac"] != response["hmac"] or message["key"] != response["key"] or message["version"] != response["version"]:
            return False
        serverValidation = {
            "key": message["key"],
            "nonce": message["nonce"],
            "version": message["version"],
            "hmac": message["hmac"],
            "serverNonce": response["serverNonce"]
        }
        serverValidationString = json.dumps(serverValidation).encode("utf-8")
        serverHash = self.generateHmac(serverValidationString, response["serverNonce"])
        return hmac.compare_digest(serverHash, response["serverSignature"])

    def verifyKey(self, key):
        nonce = self.generateNonce(64)
        message = {
            "key": key,
            "nonce": nonce,
            "version": self.currentVersion
        }
        messageString = json.dumps(message).encode("utf-8")
        messageHash = self.generateHmac(messageString, nonce)
        message["hmac"] = messageHash
        serverResp = self.sendApiRequest(self.apiEndpoint + "/authenticate", message)
        if not serverResp:
            return False
        return self.verifyServerResponse(message, serverResp)