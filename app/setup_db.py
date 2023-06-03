from pymongo import MongoClient
from dotenv import load_dotenv
import os


load_dotenv()

mongo_host = os.getenv('MONGO_HOST')
mongo_port = int(os.getenv('MONGO_PORT'))

client = MongoClient(host=mongo_host, port=mongo_port)

mongo_db = os.getenv('MONGO_DB')

# Accessing DB (it will create if it does not exist)
db = client[mongo_db]

# Create collections
db.create_collection(os.getenv('MONGO_COLLECTION_QUEUE'))
db.create_collection(os.getenv('MONGO_COLLECTION_RULES'))
db.create_collection(os.getenv('MONGO_COLLECTION_BLACKLISTED'))
db.create_collection(os.getenv('MONGO_COLLECTION_ALERTS'))

# List created collections
print(db.list_collection_names())
