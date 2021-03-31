from client import APIRequest

class APIManager:

    def __init__(self, apiEndpoint):
        self.requester = APIRequest.APIRequest(apiEndpoint)

    # This is the abstracted functionality that is exposed to users
    def verifyKey(self, key):
        return self.requester.verifyKey(key)
    
