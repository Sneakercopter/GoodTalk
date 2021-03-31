
class DatabaseUtils:

    def __init__(self):
        self.dbUrl = None

    # Connect to your database service, customise this as you see fit to your
    # database requirements.
    def connectToDB(self):
        pass

    # Key validation logic goes here, return True for valid, False for invalid
    def validateKey(self, key):
        return True