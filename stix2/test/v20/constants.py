import datetime as dt

import pytz

FAKE_TIME = dt.datetime(2017, 1, 1, 12, 34, 56, tzinfo=pytz.utc)

ATTACK_PATTERN_ID = "attack-pattern--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061"
CAMPAIGN_ID = "campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"
COURSE_OF_ACTION_ID = "course-of-action--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"
IDENTITY_ID = "identity--311b2d2d-f010-4473-83ec-1edf84858f4c"
INDICATOR_ID = "indicator--a740531e-63ff-4e49-a9e1-a0a3eed0e3e7"
INTRUSION_SET_ID = "intrusion-set--4e78f46f-a023-4e5f-bc24-71b3ca22ec29"
MALWARE_ID = "malware--9c4638ec-f1de-4ddb-abf4-1b760417654e"
MARKING_DEFINITION_ID = "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
NOTE_ID = "note--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061"
OBSERVED_DATA_ID = "observed-data--b67d30ff-02ac-498a-92f9-32f845f448cf"
RELATIONSHIP_ID = "relationship--df7c87eb-75d2-4948-af81-9d49d246f301"
REPORT_ID = "report--84e4d88f-44ea-4bcd-bbf3-b2c1c320bcb3"
SIGHTING_ID = "sighting--bfbc19db-ec35-4e45-beed-f8bde2a772fb"
THREAT_ACTOR_ID = "threat-actor--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"
TOOL_ID = "tool--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"
VULNERABILITY_ID = "vulnerability--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061"

MARKING_IDS = [
    "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "marking-definition--443eb5c3-a76c-4a0a-8caa-e93998e7bc09",
    "marking-definition--57fcd772-9c1d-41b0-8d1f-3d47713415d9",
    "marking-definition--462bf1a6-03d2-419c-b74e-eee2238b2de4",
    "marking-definition--68520ae2-fefe-43a9-84ee-2c2a934d2c7d",
    "marking-definition--2802dfb1-1019-40a8-8848-68d0ec0e417f",
]
RELATIONSHIP_IDS = [
    'relationship--06520621-5352-4e6a-b976-e8fa3d437ffd',
    'relationship--181c9c09-43e6-45dd-9374-3bec192f05ef',
    'relationship--a0cbb21c-8daf-4a7f-96aa-7155a4ef8f70',
]

# *_KWARGS contains all required arguments to create an instance of that STIX object
# *_MORE_KWARGS contains all the required arguments, plus some optional ones

ATTACK_PATTERN_KWARGS = dict(
    name="Phishing",
)

CAMPAIGN_KWARGS = dict(
    name="Green Group Attacks Against Finance",
    description="Campaign by Green Group against a series of targets in the financial services sector.",
)

CAMPAIGN_MORE_KWARGS = dict(
    type='campaign',
    id=CAMPAIGN_ID,
    created_by_ref=IDENTITY_ID,
    created="2016-04-06T20:03:00.000Z",
    modified="2016-04-06T20:03:00.000Z",
    name="Green Group Attacks Against Finance",
    description="Campaign by Green Group against a series of targets in the financial services sector.",
)

COURSE_OF_ACTION_KWARGS = dict(
    name="Block",
)

IDENTITY_KWARGS = dict(
    name="John Smith",
    identity_class="individual",
)

INDICATOR_KWARGS = dict(
    labels=['malicious-activity'],
    pattern="[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']",
)

INTRUSION_SET_KWARGS = dict(
    name="Bobcat Breakin",
)

MALWARE_KWARGS = dict(
    labels=['ransomware'],
    name="Cryptolocker",
)

MALWARE_MORE_KWARGS = dict(
    type='malware',
    id=MALWARE_ID,
    created="2016-04-06T20:03:00.000Z",
    modified="2016-04-06T20:03:00.000Z",
    labels=['ransomware'],
    name="Cryptolocker",
    description="A ransomware related to ...",
)

OBSERVED_DATA_KWARGS = dict(
    first_observed=FAKE_TIME,
    last_observed=FAKE_TIME,
    number_observed=1,
    objects={
        "0": {
            "type": "windows-registry-key",
            "key": "HKEY_LOCAL_MACHINE\\System\\Foo\\Bar",
        },
    },
)

REPORT_KWARGS = dict(
    labels=["campaign"],
    name="Bad Cybercrime",
    published=FAKE_TIME,
    object_refs=[INDICATOR_ID],
)

RELATIONSHIP_KWARGS = dict(
    relationship_type="indicates",
    source_ref=INDICATOR_ID,
    target_ref=MALWARE_ID,
)

SIGHTING_KWARGS = dict(
    sighting_of_ref=INDICATOR_ID,
)

THREAT_ACTOR_KWARGS = dict(
    labels=["crime-syndicate"],
    name="Evil Org",
)

TOOL_KWARGS = dict(
    labels=["remote-access"],
    name="VNC",
)

VULNERABILITY_KWARGS = dict(
    name="Heartbleed",
)
