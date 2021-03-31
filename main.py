import APIManager

realKey = "APENL-4N9L1-2KA9D-3JX0-44LSK"
notRealKey = "AAAAA-AAAAA-AAAAA-AAAAA-AAAAA"
apiMgr = APIManager.APIManager("https://authentication.sneakercopter.io")

# Will be valid
print("Checking key: %s" % realKey)
validity = apiMgr.verifyKey(realKey)
print("Authentication success: %s" % validity)

# Will be invalid
print("Checking key: %s" % notRealKey)
validity = apiMgr.verifyKey(notRealKey)
print("Authentication success: %s" % validity)