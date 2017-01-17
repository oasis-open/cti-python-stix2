from datetime import datetime
import json
import uuid

import pytz


def format_datetime(dt):
    # 1. Convert to UTC
    # 2. Format in isoformat
    # 3. Strip off "+00:00"
    # 4. Add "Z"
    return dt.astimezone(pytz.utc).isoformat()[:-6] + "Z"

# REQUIRED (all):
# - type
# - id
# - created
# - modified


class Indicator:
    # REQUIRED (Indicator):
    # - type
    # - labels
    # - pattern
    # - valid_from
    required = ['']

    def __init__(self, type='indicator', id=None, created=None, modified=None,
                 labels=None, pattern=None, valid_from=None):
        now = datetime.now(tz=pytz.UTC)

        if type != 'indicator':
            raise ValueError("Indicators must have type='indicator'.")
        self.type = type

        if not id:
            id = 'indicator--' + str(uuid.uuid4())
        if not id.startswith('indicator--'):
            raise ValueError("Indicator id values must begin with 'indicator--'.")
        self.id = id

        self.created = created or now
        self.modified = modified or now
        self.labels = labels
        self.pattern = pattern
        self.valid_from = valid_from or now

    def __str__(self):
        # TODO: put keys in specific order. Probably need custom JSON encoder.
        return json.dumps({
            'type': self.type,
            'id': self.id,
            'created': format_datetime(self.created),
            'modified': format_datetime(self.modified),
            'labels': self.labels,
            'pattern': self.pattern,
            'valid_from': format_datetime(self.valid_from),
        }, indent=4, sort_keys=True, separators=(",", ": "))  # Don't include spaces after commas.
