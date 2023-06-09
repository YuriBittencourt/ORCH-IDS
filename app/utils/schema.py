class Schema:
    def __init__(self):
        self.schemas = {
            'blacklist': {
                'bsonType': 'object',
                'required':
                    [
                        'ip',
                        'ip_version',
                        'reason'
                    ],
                'properties': {
                    'ip': {
                        'type': 'string'
                    },
                    'ip_version': {
                        'type': 'number',
                        'enum': [4, 6]
                    },
                    'reason': {
                        'type': 'string'
                    }
                }
            },

            'packets': {
                'bsonType': 'object',
                'required':
                    [
                        'timestamp',
                        'source_ip',
                        'destination_ip',
                        'ip_version',
                        'length',
                        'protocol',
                        'captured_by'
                    ],
                'properties': {
                    'timestamp': {
                        'type': 'number'
                    },
                    'source_ip': {
                        'type': 'string'
                    },
                    'destination_ip': {
                        'type': 'string'
                    },
                    'ip_version': {
                        'type': 'number',
                        'enum': [4, 6]
                    },
                    'length': {
                        'type': 'number'
                    },
                    'protocol': {
                        'type': 'string'
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
                    },
                    'captured_by': {
                        'type': 'string'
                    }
                }
            },

            'rules': {
                'bsonType': 'object',
                'required':
                    [
                        'name',
                        'description',
                        'severity',
                        'direction'
                    ],
                'properties': {
                    'name': {
                        'type': 'string'
                    },
                    'description': {
                        'type': 'string'
                    },
                    'severity': {
                        'type': 'number',
                        'minimum': 0
                    },
                    'direction': {
                        'type': 'boolean',
                    },
                    'source_ip': {
                        'type': 'string',
                    },
                    'destination_ip': {
                        'type': 'string',
                    },
                    'ip_version': {
                        'type': 'number',
                        'enum': [4, 6]
                    },
                    'max_length': {
                        'type': 'number',
                        'minimum': 0
                    },
                    'min_length': {
                        'type': 'number',
                        'minimum': 0
                    },
                    'protocol': {
                        'type': 'string',
                    },
                    'source_port': {
                        'type': 'number',
                        'minimum': 0,
                        'maximum': 65536
                    },
                    'destination_port': {
                        'type': 'number',
                        'minimum': 0,
                        'maximum': 65536
                    },
                    'count': {
                        'type': 'number',
                        'minimum': 1
                    },
                    'interval': {
                        'type': 'number',
                        'minimum': 1
                    },
                    'track': {
                        'type': 'string',
                        'enum': ['by_src', 'by_dst']
                    },
                    'flags': {
                        'type': 'string'
                    }
                }

            },

            'alerts': {
                'bsonType': 'object',
                'required':
                    [
                        'name',
                        'severity',
                        'timestamp',
                        'protocol',
                        'source_ip',
                        'destination_ip'
                    ],
                'properties': {
                    'name': {
                        'type': 'string'
                    },
                    'severity': {
                        'type': 'number',
                        'minimum': 0
                    },
                    'timestamp': {
                        'type': 'number',
                        'minimum': 0
                    },
                    'source_ip': {
                        'type': 'string'
                    },
                    'destination_ip': {
                        'type': 'string'
                    },
                    'length': {
                        'type': 'number',
                    },
                    'source_port': {
                        'type': 'number',
                        'minimum': 0,
                        'maximum': 65536
                    },
                    'destination_port': {
                        'type': 'number',
                        'minimum': 0,
                        'maximum': 65536
                    }
                }
            }
        }

        self.indexes = {
            'blacklist': [{'value': 'ip', 'unique': True}],
            'packets': [{'value': [('timestamp', 1)], 'unique': False}],
            'rules': [{'value': 'name', 'unique': True}, {'value': [('severity', -1)], 'unique': False}],
            'alerts': [{'value': [('severity', -1), ('timestamp', -1)], 'unique': False}]
        }


schemas = Schema().schemas
