from datetime import datetime

from pymongo import MongoClient
from dotenv import dotenv_values

from apscheduler.schedulers.background import BackgroundScheduler


def create_incident(name, packet, severity=None):
    new_alert = {
        'name': name,
        'timestamp': packet['timestamp'],
        'protocol': packet['protocol'],
        'source_ip': packet['source_ip'],
        'destination_ip': packet['source_ip'],
        'length': packet['length']
    }

    if severity:
        new_alert['severity'] = severity

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
        self.occurrences = db[config['MONGO_COLLECTION_OCCURRENCES']]

        # Should not evaluate these fields:
        self.ignored_fields = ['name', 'severity', 'description', 'direction', 'count', 'interval', 'track']

        self.rule_set = []
        self.complex_rule_set = {}  # for rules that have count, interval and track attributes

        self.blacklist_set = {}  # blacklisted IPs (key is Ip and value is severity)

    def fetch_rules(self):
        rules_list = list(self.rules.aggregate([
            {'$project': {'_id': 0}},
            {'$sort': {'severity': -1}}
        ]))

        new_complex_rules = {}
        new_rules = []
        for r in rules_list:
            # check if a rule has count and interval (it can have a track attribute as well)
            # if it has then it is a complex rule and should be evaluated a little different
            if 'count' in r and 'interval' in r:
                new_complex_rules[r['name']] = {k: v for k, v in r.items() if k in ['name', 'count', 'interval', 'track', 'severity']}

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
        self.complex_rule_set = new_complex_rules

    def fetch_blacklist(self):
        self.blacklist_set = {
            x['ip']: x['severity'] for x in list(
                self.blacklist.find(
                    {},
                    projection={
                        '_id': 0,
                        'ip': 1,
                        'severity': 1
                    }
                )
            )
        }

    def fetch_packets(self, batch_size=10):
        packet_list = list(self.packets.find({}, sort=[('timestamp', 1)], limit=batch_size))
        self.packets.delete_many({"_id": {'$in': [x['_id'] for x in packet_list]}})
        return packet_list

    def save_alerts(self, alerts_list):
        if len(alerts_list):
            self.alerts.insert_many(alerts_list)

    def save_occurrences(self, occurrences_list):
        if len(occurrences_list):
            self.occurrences.insert_many(occurrences_list)

    def verify(self, packet, rule):
        for k, v in rule.items():
            if k in self.ignored_fields:
                continue

            if k == 'flags':
                if 'flags' not in packet or v not in packet['flags']:
                    return False
            elif k == 'min_length':
                if v < packet[k]:
                    return False
            elif k == 'max_length':
                if v > packet[k]:
                    return False
            elif v != packet[k]:
                return False
        return True

    def check_blacklist(self, packet):
        blacklist_alert = []
        if packet['source_ip'] in self.blacklist_set:
            blacklist_alert.append(create_incident('BLACKLISTED_IP_SRC',
                                                   packet,
                                                   self.blacklist_set[packet['source_ip']]))

        if packet['destination_ip'] in self.blacklist_set:
            blacklist_alert.append(create_incident('BLACKLISTED_IP_DST',
                                                   packet,
                                                   self.blacklist_set[packet['destination_ip']]))

        return blacklist_alert

    def alert_complex_rules(self):
        new_alerts = []
        for rule in self.complex_rule_set.values():

            # Group by interval
            group = {'timestamp': {
                '$dateTrunc': {
                    'date': {
                        '$toDate': '$timestamp'
                    },
                    'unit': 'second',
                    'binSize': int(rule['interval'])
                }
            }
            }

            if 'track' in rule:
                if rule['track'] == 'both' or rule['track'] == 'by_dst':
                    group['destination_ip'] = '$destination_ip'

                elif rule['track'] == 'both' or rule['track'] == 'by_src':
                    group['source_ip'] = '$source_ip'

            occurrences = self.occurrences.aggregate([
                {
                    '$match': {
                        'name': rule['name']
                    }
                }, {
                    '$group': {
                        '_id': group,
                        'count': {
                            '$sum': 1
                        },
                        'packet': {
                            '$last': '$$CURRENT'
                        }
                    }
                }, {
                    '$match': {
                        'count': {
                            '$gte': int(rule['count'])
                        }
                    }
                }
            ])

            for occurrence in occurrences:
                new_alerts.append(create_incident(occurrence['packet']['name'], occurrence['packet'], rule['severity']))

            # We can simply delete everyone that has its timestamp lesser than (now - interval)
            self.occurrences.delete_many({'name': rule['name'], 'timestamp': {'$lte': int(datetime.now().timestamp() * 1000) - int(rule['interval']) * 1000}})
        self.save_alerts(new_alerts)


if __name__ == '__main__':
    enforcer = Enforcer()

    scheduler = BackgroundScheduler()
    # Refresh rules and blacklist every 5 minutes
    scheduler.add_job(enforcer.fetch_rules, 'interval', minutes=5)
    scheduler.add_job(enforcer.fetch_blacklist, 'interval', minutes=5)

    scheduler.add_job(enforcer.alert_complex_rules, 'interval', minutes=1)

    enforcer.fetch_rules()
    enforcer.fetch_blacklist()

    scheduler.start()

    try:
        while True:
            new_alerts = []
            new_occurrences = []
            for packet in enforcer.fetch_packets():

                # Check if any Ip (Source, Destination) is blacklisted
                new_alerts += enforcer.check_blacklist(packet)

                # Try rules in a severity descending order stopping at first match
                for rule in enforcer.rule_set:

                    if enforcer.verify(packet, rule):

                        # check if it is a complex rule or not:
                        if rule['name'] not in enforcer.complex_rule_set:
                            # In this case just alert
                            new_alerts.append(create_incident(rule['name'], packet, rule['severity']))
                        else:
                            # Complex rule case:
                            new_occurrences.append(create_incident(rule['name'], packet))
                        break

            # Saving
            enforcer.save_occurrences(new_occurrences)
            enforcer.save_alerts(new_alerts)

    except (KeyboardInterrupt, SystemExit):
        scheduler.shutdown()