class Schema:
    def __init__(self):
        self.schemas = {
            'blacklist': {
                'bsonType': 'object',
                'required':
                    [
                        'ip',
                        'version',
                        'reason'
                    ],
                'properties': {
                    'ip': {
                        'type': 'string'
                    },
                    'version': {
                        'type': 'number',
                        'enum': [4, 6]
                    },
                    'reason': {
                        'type': 'string',
                    }
                }
            },

            'packets': {
                'bsonType': 'object',
                'required':
                    [
                        'timestamp',
                        'source_mac',
                        'destination_mac',
                        'source_ip',
                        'destination_ip',
                        'version',
                        'length',
                        'protocol'
                    ],
                'properties': {
                    'timestamp': {
                        'type': 'number',
                    },
                    'source_mac': {
                        'type': 'string',
                    },
                    'destination_mac': {
                        'type': 'string',
                    },
                    'source_ip': {
                        'type': 'string',
                    },
                    'destination_ip': {
                        'type': 'string',
                    },
                    'version': {
                        'type': 'number',
                        'enum' : [4,6],
                    },
                    'length': {
                        'type': 'number',
                    },
                    'protocol': {
                        'type': 'string',
                    },
                    'source_port': {
                        'type': 'number'
                    },
                    'destination_port': {
                        'type': 'number'
                    },

                    'flags': {
                        'type': 'array',
                        'items': {
                            'type': 'string'
                        }
                    }
                }
            },

            'rules': {},

            'alerts': {}
        }

        self.indexes = {
            'blacklist': [{'value': 'ip', 'unique': True}],
            'packets': [{'value': [('timestamp', 1)], 'unique': False}]
        }