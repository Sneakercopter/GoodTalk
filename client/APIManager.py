import APIRequest

class APIManager:

    def __init__(self, apiEndpoint):
        self.requester = APIRequest.APIRequest(apiEndpoint)

    def verifyKey(self, key):
        return self.requester.verifyKey(key)
    
