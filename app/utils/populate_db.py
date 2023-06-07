from .mongo import mongo_instance as mongo


def blacklist():
    documents =[
        {"ip": "192.164.0.32", "version": 4, "reason": "botnet"},
        {"ip": "192.164.2.32", "version": 4, "reason": "suspicious"},
        {"ip": "2001:0db8:85a3:0000:0000:8a2e:0370:7334", "version": 6, "reason": "botnet"},
        {"ip": "2001:0db8:85a3:0000:0000:8a2e:0370:7335", "version": 6, "reason": "suspicious"},
    ]
    mongo.db[mongo.collections['blacklist']].delete_many({})
    mongo.db[mongo.collections['blacklist']].insert_many(documents, ordered=False)


def packets():
    documents =[
        {
            "timestamp": 1686044761376,
            "source_mac": "70:85:c2:48:2d:23",
            "destination_mac": "6c:5a:b0:8c:45:cb",
            "source_ip": "192.168.0.114",
            "destination_ip": "66.22.246.136",
            "version": 4,
            "length": 300,
            "protocol": "UDP",
            "source_port": 54380,
            "destination_port": 50002
        },
        {
            "timestamp": 1686044761380,
            "source_mac": "70:85:c2:48:2d:23",
            "destination_mac": "6c:5a:b0:8c:45:cb",
            "source_ip": "192.168.0.114",
            "destination_ip": "66.22.246.136",
            "version": 4,
            "length": 300,
            "protocol": "UDP",
            "source_port": 54380,
            "destination_port": 50002
        },
        {
            "timestamp": 1686044761381,
            "source_mac": "70:85:c2:48:2d:23",
            "destination_mac": "6c:5a:b0:8c:45:cb",
            "source_ip": "192.168.0.114",
            "destination_ip": "66.22.246.136",
            "version": 4,
            "length": 300,
            "protocol": "UDP",
            "source_port": 54380,
            "destination_port": 50002
        },
        {
            "timestamp": 1686044761434,
            "source_mac": "70:85:c2:48:2d:23",
            "destination_mac": "6c:5a:b0:8c:45:cb",
            "source_ip": "192.168.0.114",
            "destination_ip": "162.159.129.235",
            "version": 4,
            "length": 127,
            "protocol": "TCP",
            "source_port": 58964,
            "destination_port": 443,
            "flags": [
                "P",
                "A"
            ]
        },
        {
            "timestamp": 1686044761447,
            "source_mac": "70:85:c2:48:2d:23",
            "destination_mac": "6c:5a:b0:8c:45:cb",
            "source_ip": "192.168.0.114",
            "destination_ip": "35.215.218.63",
            "version": 4,
            "length": 71,
            "protocol": "UDP",
            "source_port": 55612,
            "destination_port": 50002
        },
        {
            "timestamp": 1686044761452,
            "source_mac": "6c:5a:b0:8c:45:cb",
            "destination_mac": "70:85:c2:48:2d:23",
            "source_ip": "162.159.129.235",
            "destination_ip": "192.168.0.114",
            "version": 4,
            "length": 40,
            "protocol": "TCP",
            "source_port": 443,
            "destination_port": 58964,
            "flags": [
                "A"
            ]
        }
    ]
    mongo.db[mongo.collections['packets']].delete_many({})
    mongo.db[mongo.collections['packets']].insert_many(documents, ordered=False)


def rules():
    documents = [
        {'name': "PING",
         'description': "someone pinged the host 192.168.0.124",
         'severity':  2,
         'direction': 'in',
         'source_ip': "177.230.25.122",
         'destination_ip': '192.168.0.124',
         'ip_version': 4,
         'protocol': 'ICMP',
         },
    ]
    mongo.db[mongo.collections['rules']].delete_many({})
    mongo.db[mongo.collections['rules']].insert_many(documents, ordered=False)


def alerts():
    pass
