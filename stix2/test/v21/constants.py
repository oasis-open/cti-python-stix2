import datetime as dt

import pytz

FAKE_TIME = dt.datetime(2017, 1, 1, 12, 34, 56, tzinfo=pytz.utc)

ATTACK_PATTERN_ID = "attack-pattern--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061"
CAMPAIGN_ID = "campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"
COURSE_OF_ACTION_ID = "course-of-action--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"
GROUPING_ID = "grouping--753abcde-3141-5926-ace5-0a810b1ff996"
IDENTITY_ID = "identity--311b2d2d-f010-4473-83ec-1edf84858f4c"
INCIDENT_ID = "incident--40fc3b35-0dc4-4afd-9927-288d44bfce20"
INDICATOR_ID = "indicator--a740531e-63ff-4e49-a9e1-a0a3eed0e3e7"
INFRASTRUCTURE_ID = "infrastructure--3000ae1b-784c-f03d-8abc-0a625b2ff018"
INTRUSION_SET_ID = "intrusion-set--4e78f46f-a023-4e5f-bc24-71b3ca22ec29"
LOCATION_ID = "location--a6e9345f-5a15-4c29-8bb3-7dcc5d168d64"
MALWARE_ID = "malware--9c4638ec-f1de-4ddb-abf4-1b760417654e"
MALWARE_ANALYSIS_ID = "malware-analysis--b46ee0ad-9443-41c5-a8e3-0fa053262805"
MARKING_DEFINITION_ID = "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
NOTE_ID = "note--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061"
OBSERVED_DATA_ID = "observed-data--b67d30ff-02ac-498a-92f9-32f845f448cf"
OPINION_ID = "opinion--b01efc25-77b4-4003-b18b-f6e24b5cd9f7"
REPORT_ID = "report--84e4d88f-44ea-4bcd-bbf3-b2c1c320bcb3"
RELATIONSHIP_ID = "relationship--df7c87eb-75d2-4948-af81-9d49d246f301"
THREAT_ACTOR_ID = "threat-actor--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"
TOOL_ID = "tool--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"
SIGHTING_ID = "sighting--bfbc19db-ec35-4e45-beed-f8bde2a772fb"
VULNERABILITY_ID = "vulnerability--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061"

EXTENSION_DEFINITION_IDS = [
    "extension-definition--1f611280-fbe1-48e8-92ab-ff47ce02d5b7",  # new-sdo
    "extension-definition--368f4787-5b43-467c-9693-0c9de4289c4b",  # property-extension
    "extension-definition--dd73de4f-a7f3-49ea-8ec1-8e884196b7a8",  # top-level-property-extension
    "extension-definition--150c1738-28c9-44d0-802d-70523218240b",  # new-sdo, new-sco, property-extension
]
MARKING_IDS = [
    "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "marking-definition--443eb5c3-a76c-4a0a-8caa-e93998e7bc09",
    "marking-definition--57fcd772-9c1d-41b0-8d1f-3d47713415d9",
    "marking-definition--462bf1a6-03d2-419c-b74e-eee2238b2de4",
    "marking-definition--68520ae2-fefe-43a9-84ee-2c2a934d2c7d",
    "marking-definition--2802dfb1-1019-40a8-8848-68d0ec0e417f",
]
MARKING_LANGS = [
    "en",
    "es",
    "de",
    "ja",
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
    spec_version='2.1',
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

GROUPING_KWARGS = dict(
    name="Harry Potter and the Leet Hackers",
    context="suspicious-activity",
    object_refs=[
        "malware--c8d2fae5-7271-400c-b81d-931a4caf20b9",
        "identity--988145ed-a3b4-4421-b7a7-273376be67ce",
    ],
)

IDENTITY_KWARGS = dict(
    name="John Smith",
    identity_class="individual",
)

INDICATOR_KWARGS = dict(
    indicator_types=['malicious-activity'],
    pattern_type="stix",
    pattern="[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']",
    valid_from="2017-01-01T12:34:56Z",
)

INFRASTRUCTURE_KWARGS = dict(
    name="Poison Ivy C2",
    infrastructure_types=["command-and-control"],
)

INTRUSION_SET_KWARGS = dict(
    name="Bobcat Breakin",
)

LOCATION_KWARGS = dict(
    region="africa",
)

MALWARE_KWARGS = dict(
    malware_types=['ransomware'],
    name="Cryptolocker",
    is_family=False,
)

MALWARE_MORE_KWARGS = dict(
    type='malware',
    id=MALWARE_ID,
    created="2016-04-06T20:03:00.000Z",
    modified="2016-04-06T20:03:00.000Z",
    malware_types=['ransomware'],
    name="Cryptolocker",
    description="A ransomware related to ...",
    is_family=False,
)

MALWARE_ANALYSIS_KWARGS = dict(
    product="microsoft",
    result="malicious",
)

NOTE_KWARGS = dict(
    content="Heartbleed",
    object_refs=[CAMPAIGN_ID],
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

OPINION_KWARGS = dict(
    opinion="agree",
    object_refs=[CAMPAIGN_ID],
)

REPORT_KWARGS = dict(
    report_types=["campaign"],
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
    threat_actor_types=["crime-syndicate"],
    name="Evil Org",
)

TOOL_KWARGS = dict(
    tool_types=["remote-access"],
    name="VNC",
)

VULNERABILITY_KWARGS = dict(
    name="Heartbleed",
)
