from .mongo import mongo_instance as mongo
from .schema import Schema


def setup_db():
    schema = Schema()

    # Drop collections if they do exist and create:
    for collection in mongo.collections:
        mongo.db.drop_collection(collection)
        mongo.db.create_collection(collection, validator={'$jsonSchema': schema.schemas[collection]})

        # create index if there is a index
        if collection in schema.indexes:
            for index in schema.indexes[collection]:
                mongo.db[collection].create_index(index['value'], unique=index['unique'])

    # List created collections:
    print(mongo.db.list_collection_names())