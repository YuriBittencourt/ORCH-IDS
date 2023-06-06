from mongo import Mongo

class Populate:

    def __init__(self):
        self._mongo = Mongo()

    def rules(self):
        pass

    def blacklist(self):
        self._mongo.db[self._mongo.collections['blacklist']].insert_many([
            {"ip": "192.164.0.32", "version": 4, "reason": "botnet"},
            {"ip": "192.164.2.32", "version": 4, "reason": "suspeito"},
            {"ip": "ff8d", "version": 6, "reason": "botnet"},
            {"ip": "ff4c", "version": 4, "reason": "suspeito"},
        ]
        )

    def packets(self):
        pass

    def alerts(self):
        pass


Populate().blacklist()