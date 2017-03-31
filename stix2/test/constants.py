import datetime as dt

import pytz

FAKE_TIME = dt.datetime(2017, 1, 1, 12, 34, 56, tzinfo=pytz.utc)

INDICATOR_ID = "indicator--01234567-89ab-cdef-0123-456789abcdef"
MALWARE_ID = "malware--fedcba98-7654-3210-fedc-ba9876543210"
RELATIONSHIP_ID = "relationship--00000000-1111-2222-3333-444444444444"
IDENTITY_ID = "identity--d4d765ce-cff7-40e8-b7a6-e205d005ac2c"
SIGHTING_ID = "sighting--bfbc19db-ec35-4e45-beed-f8bde2a772fb"

# Minimum required args for an Indicator instance
INDICATOR_KWARGS = dict(
    labels=['malicious-activity'],
    pattern="[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']",
)

# Minimum required args for a Malware instance
MALWARE_KWARGS = dict(
    labels=['ransomware'],
    name="Cryptolocker",
)

# Minimum required args for a Relationship instance
RELATIONSHIP_KWARGS = dict(
    relationship_type="indicates",
    source_ref=INDICATOR_ID,
    target_ref=MALWARE_ID,
)

SIGHTING_KWARGS = dict(
    sighting_of_ref=INDICATOR_ID,
)
