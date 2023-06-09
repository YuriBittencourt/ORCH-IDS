from .mongo import mongo_instance as mongo


def drop_blacklist():
    mongo.db[mongo.collections['blacklist']].delete_many({})


def populate_blacklist():
    documents =[
        {'ip': '192.164.0.32', 'ip_version': 4, 'reason': 'botnet', 'severity': 5},
        {'ip': '192.164.2.32', 'ip_version': 4, 'reason': 'suspicious', 'severity': 5},
        {'ip': '2001:0db8:85a3:0000:0000:8a2e:0370:7334', 'ip_version': 6, 'reason': 'botnet', 'severity': 5},
        {'ip': '2001:0db8:85a3:0000:0000:8a2e:0370:7335', 'ip_version': 6, 'reason': 'suspicious', 'severity': 5},
    ]
    mongo.db[mongo.collections['blacklist']].insert_many(documents, ordered=False)


def drop_packets():
    mongo.db[mongo.collections['packets']].delete_many({})


def populate_packets():
    documents =[
        {
            'timestamp': 1686044761376,
            'source_ip': '192.168.0.114',
            'destination_ip': '66.22.246.136',
            'ip_version': 4,
            'length': 300,
            'protocol': 'UDP',
            'source_port': 54380,
            'destination_port': 50002,
            'captured_by': 'dummy'
        },
        {
            'timestamp': 1686044761380,
            'source_ip': '192.168.0.114',
            'destination_ip': '66.22.246.136',
            'ip_version': 4,
            'length': 300,
            'protocol': 'UDP',
            'source_port': 54380,
            'destination_port': 50002,
            'captured_by': 'dummy'
        },
        {
            'timestamp': 1686044761381,
            'source_ip': '192.168.0.114',
            'destination_ip': '66.22.246.136',
            'ip_version': 4,
            'length': 300,
            'protocol': 'UDP',
            'source_port': 54380,
            'destination_port': 50002,
            'captured_by': 'dummy'
        },
        {
            'timestamp': 1686044761434,
            'source_ip': '192.168.0.114',
            'destination_ip': '162.159.129.235',
            'ip_version': 4,
            'length': 127,
            'protocol': 'TCP',
            'source_port': 58964,
            'destination_port': 443,
            'flags': [
                'P',
                'A'
            ],
            'captured_by': 'dummy'
        },
        {
            'timestamp': 1686044761447,
            'source_ip': '192.168.0.114',
            'destination_ip': '35.215.218.63',
            'ip_version': 4,
            'length': 71,
            'protocol': 'UDP',
            'source_port': 55612,
            'destination_port': 50002,
            'captured_by': 'dummy'
        },
        {
            'timestamp': 1686044761452,
            'source_ip': '162.159.129.235',
            'destination_ip': '192.168.0.114',
            'ip_version': 4,
            'length': 40,
            'protocol': 'TCP',
            'source_port': 443,
            'destination_port': 58964,
            'flags': [
                'A'
            ],
            'captured_by': 'dummy'
        }
    ]
    mongo.db[mongo.collections['packets']].insert_many(documents, ordered=False)


def drop_rules():
    mongo.db[mongo.collections['rules']].delete_many({})


def populate_rules():
    documents = [
        {
            'name': 'PING',
            'description': 'someone pinged the host 192.168.0.124',
            'severity':  2,
            'direction': True,
            'source_ip': '177.230.25.122',
            'destination_ip': '192.168.0.124',
            'ip_version': 4,
            'protocol': 'ICMP',
        },
        {
            'name': 'PortScan',
            'description': 'someone portscanned the host 192.168.0.120',
            'severity': 2,
            'direction': True,
            'destination_ip': '192.168.0.120',
            'min_length': 10,
            'ip_version': 4,
            'protocol': 'TCP',
            'count': 40,
            'interval': 10
        },
    ]
    mongo.db[mongo.collections['rules']].insert_many(documents, ordered=False)


def drop_alerts():
    mongo.db[mongo.collections['alerts']].delete_many({})


def populate_alerts():
    documents = [
        {
            'name': 'PING',
            'severity': 2,
            'timestamp': 1686044761376,
            'protocol': 'ICMP',
            'source_ip': '192.168.0.120',
            'destination_ip': '192.168.0.124'
        },

        {
            'name': 'PortScan',
            'severity': 2,
            'timestamp': 1686044761377,
            'protocol': 'TCP',
            'source_ip': '192.168.0.125',
            'destination_ip': '192.168.0.120'
        },
    ]
    mongo.db[mongo.collections['alerts']].insert_many(documents, ordered=False)

