import datetime as dt

import pytz

FAKE_TIME = dt.datetime(2017, 1, 1, 12, 34, 56, tzinfo=pytz.utc)

ATTACK_PATTERN_ID = "attack-pattern--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061"
CAMPAIGN_ID = "campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"
COURSE_OF_ACTION_ID = "course-of-action--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"
IDENTITY_ID = "identity--311b2d2d-f010-5473-83ec-1edf84858f4c"
INDICATOR_ID = "indicator--01234567-89ab-cdef-0123-456789abcdef"
INTRUSION_SET_ID = "intrusion-set--4e78f46f-a023-4e5f-bc24-71b3ca22ec29"
MALWARE_ID = "malware--fedcba98-7654-3210-fedc-ba9876543210"
MARKING_DEFINITION_ID = "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
OBSERVED_DATA_ID = "observed-data--b67d30ff-02ac-498a-92f9-32f845f448cf"
REPORT_ID = "report--84e4d88f-44ea-4bcd-bbf3-b2c1c320bcb3"
RELATIONSHIP_ID = "relationship--00000000-1111-2222-3333-444444444444"
THREAT_ACTOR_ID = "threat-actor--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"
TOOL_ID = "tool--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"
SIGHTING_ID = "sighting--bfbc19db-ec35-4e45-beed-f8bde2a772fb"
VULNERABILITY_ID = "vulnerability--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061"

MARKING_IDS = [
    "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "marking-definition--443eb5c3-a76c-4a0a-8caa-e93998e7bc09",
    "marking-definition--57fcd772-9c1d-41b0-8d1f-3d47713415d9",
    "marking-definition--462bf1a6-03d2-419c-b74e-eee2238b2de4",
    "marking-definition--68520ae2-fefe-43a9-84ee-2c2a934d2c7d",
    "marking-definition--2802dfb1-1019-40a8-8848-68d0ec0e417f",
]

# All required args for a Campaign instance, plus some optional args
CAMPAIGN_MORE_KWARGS = dict(
    type='campaign',
    id=CAMPAIGN_ID,
    created_by_ref="identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
    created="2016-04-06T20:03:00.000Z",
    modified="2016-04-06T20:03:00.000Z",
    name="Green Group Attacks Against Finance",
    description="Campaign by Green Group against a series of targets in the financial services sector.",
)

# Minimum required args for an Identity instance
IDENTITY_KWARGS = dict(
    name="John Smith",
    identity_class="individual",
)

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

# All required args for a Malware instance, plus some optional args
MALWARE_MORE_KWARGS = dict(
    type='malware',
    id=MALWARE_ID,
    created="2016-04-06T20:03:00.000Z",
    modified="2016-04-06T20:03:00.000Z",
    labels=['ransomware'],
    name="Cryptolocker",
    description="A ransomware related to ..."
)

# Minimum required args for a Relationship instance
RELATIONSHIP_KWARGS = dict(
    relationship_type="indicates",
    source_ref=INDICATOR_ID,
    target_ref=MALWARE_ID,
)

# Minimum required args for a Sighting instance
SIGHTING_KWARGS = dict(
    sighting_of_ref=INDICATOR_ID,
)
