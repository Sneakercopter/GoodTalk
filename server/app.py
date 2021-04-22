import json
import hashlib
import hmac
import time
import ServerUtils
import DatabaseUtils

servUtils = ServerUtils.ServerUtils()
dbUtilts = DatabaseUtils.DatabaseUtils()

def handler(event, context):
    #body
    try:
        data = json.loads(event["body"])
        key = str(data["key"])
        nonce = str(data["nonce"])
        version = str(data["version"])
        _hmac = str(data["hmac"])
        # We don't look at anything before we verify message integrity
        if not servUtils.verifyHmac(key, nonce, version, _hmac):
            return {
                'statusCode': 403,
                'headers': { "Content-Type": "application/json" },
                'body': json.dumps({"error": "Not Allowed"})
            }
        # Check further parameters - this time we can respond with more helpful messages
        if not servUtils.verifyVersion(version):
            return {
                'statusCode': 403,
                'headers': { "Content-Type": "application/json" },
                'body': json.dumps({"error": "version_not_allowed"})
            }
        # Now validate the key
        if not dbUtilts.validateKey(key):
            return {
                'statusCode': 403,
                'headers': { "Content-Type": "application/json" },
                'body': json.dumps({"error": "key_invalid"})
            }
        # If everything else is fine, we can add our signature and respond
        serverResponse = servUtils.signResponse(key, nonce, version, _hmac)
        return {
            'statusCode': 200,
            'headers': { "Content-Type": "application/json" },
            'body': json.dumps(serverResponse)
        }
    except:
        return {
            'statusCode': 403,
            'headers': { "Content-Type": "application/json" },
            'body': json.dumps({"error": "Not Allowed"})
        }
