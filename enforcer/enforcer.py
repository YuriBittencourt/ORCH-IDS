from pymongo import MongoClient
from dotenv import dotenv_values

from apscheduler.schedulers.background import BackgroundScheduler


def create_alert(name, severity, packet):
    new_alert = {
        'name': name,
        'severity': severity,
        'timestamp': packet['timestamp'],
        'protocol': packet['protocol'],
        'source_ip': packet['source_ip'],
        'destination_ip': packet['source_ip'],
        'length': packet['length']
    }

    if 'source_port' in packet:
        new_alert['source_port'] = packet['source_port']
        new_alert['destination_port'] = packet['destination_port']

    return new_alert


class Enforcer:
    def __init__(self):
        config = dotenv_values()

        mongo_db = config['MONGO_DB']
        client = MongoClient(host=config['MONGO_HOST'], port=int(config['MONGO_PORT']))
        db = client[mongo_db]

        self.rules = db[config['MONGO_COLLECTION_RULES']]
        self.alerts = db[config['MONGO_COLLECTION_ALERTS']]
        self.packets = db[config['MONGO_COLLECTION_QUEUE']]
        self.blacklist = db[config['MONGO_COLLECTION_BLACKLISTED']]

        self.ignored_fields = ['name', 'severity', 'description', 'direction', 'count', 'interval', 'track']

        self.rule_set = []
        self.blacklist_set = {}

    def fetch_rules(self):
        rules_list = list(self.rules.aggregate(
            [
                {
                    '$project':
                        {
                            '_id': 0,
                        },
                },
                {
                    '$sort':
                        {
                            'severity': -1,
                        },
                }
            ]))

        new_rules = []
        for r in rules_list:
            if not r['direction']:
                new_rule = r.copy()

                keys_to_delete = ['source_ip', 'destination_ip', 'source_port', 'destination_port']
                for k in keys_to_delete:
                    if k in new_rule:
                        del new_rule[k]

                if 'source_ip' in r:
                    new_rule['destination_ip'] = r['source_ip']
                if 'destination_ip' in r:
                    new_rule['source_ip'] = r['destination_ip']
                if 'source_port' in r:
                    new_rule['destination_port'] = r['source_port']
                if 'destination_port' in r:
                    new_rule['source_port'] = r['destination_port']
                new_rules.append(new_rule)
        self.rule_set = rules_list + new_rules

    def fetch_blacklist(self):
        self.blacklist_set = {x['ip']: x['severity'] for x in list(self.blacklist.find({}, projection={
            '_id': 0,
            'ip': 1,
            'severity': 1
        }))}

    def fetch_packets(self, batch_size=10):
        packet_list = list(self.packets.find({}, sort=[('timestamp', 1)], limit=batch_size))
        self.packets.delete_many({"_id": {'$in': [x['_id'] for x in packet_list]}})
        return packet_list

    def save_alerts(self, alerts_list):
        if len(alerts_list):
            self.alerts.insert_many(alerts_list)

    def verify(self, packet, rule):
        for k, v in rule.items():
            if k in self.ignored_fields:
                continue

            if k == 'min_length':
                if v < packet[k]:
                    return False
            elif k == 'max_length':
                if v > packet[k]:
                    return False
            elif v != packet[k]:
                return False
        return True


if __name__ == '__main__':
    enforcer = Enforcer()

    scheduler = BackgroundScheduler()
    # Refresh rules and blacklist every 5 minutes
    scheduler.add_job(enforcer.fetch_rules, 'interval', minutes=5)
    scheduler.add_job(enforcer.fetch_blacklist, 'interval', minutes=5)
    scheduler.start()

    enforcer.fetch_rules()
    enforcer.fetch_blacklist()

    try:
        while True:
            new_alerts = []
            for packet in enforcer.fetch_packets():
                if packet['source_ip'] in enforcer.blacklist_set:
                    new_alerts.append(create_alert('BLACKLISTED_IP_SRC', enforcer.blacklist_set[packet['source_ip']], packet))
                if packet['destination_ip'] in enforcer.blacklist_set:
                    new_alerts.append(create_alert('BLACKLISTED_IP_DST', enforcer.blacklist_set[packet['destination_ip']], packet))
                for rule in enforcer.rule_set:
                    if enforcer.verify(packet, rule):
                        if "count" not in rule:
                            # In this case, the rule has no count nor interval
                            new_alerts.append(create_alert(rule['name'], rule['severity'], packet))
                        else:
                            # TODO LOGIC FOR COMPLEX RULES
                            pass
                        break
            enforcer.save_alerts(new_alerts)

    except (KeyboardInterrupt, SystemExit):
        scheduler.shutdown()



