from flask import Flask
from flask import request
import json
import hashlib
import hmac
import time
import ServerUtils
import DatabaseUtils

app = Flask(__name__)
servUtils = ServerUtils.ServerUtils()
dbUtilts = DatabaseUtils.DatabaseUtils()

@app.route("/health", methods=["GET"])
def health():
    # First rule, always make your health check endpoints have pop culture reference easter eggs
    return json.dumps({"status": "Still Alive"}), 200, {'Content-Type': 'application/json'}

@app.route("/authenticate", methods=["POST"])
def authenticate():
    try:
        data = request.get_json()
        key = str(data["key"])
        nonce = str(data["nonce"])
        version = str(data["version"])
        _hmac = str(data["hmac"])
        # We don't look at anything before we verify message integrity
        if not servUtils.verifyHmac(key, nonce, version, _hmac):
            return json.dumps({"error": "Not Allowed"}), 403, {'Content-Type': 'application/json'}
        # Check further parameters - this time we can respond with more helpful messages
        if not servUtils.verifyVersion(version):
            return json.dumps({"error": "version_not_allowed"}), 403, {'Content-Type': 'application/json'}
        # Now validate the key
        if not dbUtilts.validateKey(key):
            return json.dumps({"error": "key_invalid"}), 403, {'Content-Type': 'application/json'} 
        # If everything else is fine, we can add our signature and respond
        serverResponse = servUtils.signResponse(key, nonce, version, _hmac)
        return json.dumps(serverResponse), 200, {'Content-Type': 'application/json'}
    except Exception as e:
        print(e)
        # Any error that is raised from our strict standards will be caused by a non-legitmate client. Simply 403 
        # them and provide no details on the error. WAF will take care of spammers.
        return json.dumps({"error": "Not Allowed"}), 403, {'Content-Type': 'application/json'}