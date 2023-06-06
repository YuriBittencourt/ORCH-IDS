from pymongo import MongoClient
from dotenv import dotenv_values


class Mongo:
    def __init__(self):
        config = dotenv_values()
        client = MongoClient(host=config['MONGO_HOST'], port=int(config['MONGO_PORT']))
        self.db = client[config['MONGO_DB']]
        self.collections = {
            'packets': config['MONGO_COLLECTION_QUEUE'],
            'rules': config['MONGO_COLLECTION_RULES'],
            'blacklist': config['MONGO_COLLECTION_BLACKLISTED'],
            'alerts': config['MONGO_COLLECTION_ALERTS']
        }
