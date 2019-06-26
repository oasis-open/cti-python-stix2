import datetime as dt

import pytest
import pytz

import stix2

from .constants import ATTACK_PATTERN_ID

EXPECTED = """{
    "type": "attack-pattern",
    "id": "attack-pattern--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061",
    "created": "2016-05-12T08:17:27.000Z",
    "modified": "2016-05-12T08:17:27.000Z",
    "name": "Spear Phishing",
    "description": "...",
    "external_references": [
        {
            "source_name": "capec",
            "external_id": "CAPEC-163"
        }
    ]
}"""


def test_attack_pattern_example():
    ap = stix2.v20.AttackPattern(
        id=ATTACK_PATTERN_ID,
        created="2016-05-12T08:17:27.000Z",
        modified="2016-05-12T08:17:27.000Z",
        name="Spear Phishing",
        external_references=[{
            "source_name": "capec",
            "external_id": "CAPEC-163",
        }],
        description="...",
    )

    assert str(ap) == EXPECTED


@pytest.mark.parametrize(
    "data", [
        EXPECTED,
        {
            "type": "attack-pattern",
            "id": ATTACK_PATTERN_ID,
            "created": "2016-05-12T08:17:27.000Z",
            "modified": "2016-05-12T08:17:27.000Z",
            "description": "...",
            "external_references": [
                {
                    "external_id": "CAPEC-163",
                    "source_name": "capec",
                },
            ],
            "name": "Spear Phishing",
        },
    ],
)
def test_parse_attack_pattern(data):
    ap = stix2.parse(data, version="2.0")

    assert ap.type == 'attack-pattern'
    assert ap.id == ATTACK_PATTERN_ID
    assert ap.created == dt.datetime(2016, 5, 12, 8, 17, 27, tzinfo=pytz.utc)
    assert ap.modified == dt.datetime(2016, 5, 12, 8, 17, 27, tzinfo=pytz.utc)
    assert ap.description == "..."
    assert ap.external_references[0].external_id == 'CAPEC-163'
    assert ap.external_references[0].source_name == 'capec'
    assert ap.name == "Spear Phishing"


def test_attack_pattern_invalid_labels():
    with pytest.raises(stix2.exceptions.InvalidValueError):
        stix2.v20.AttackPattern(
            id=ATTACK_PATTERN_ID,
            created="2016-05-12T08:17:27Z",
            modified="2016-05-12T08:17:27Z",
            name="Spear Phishing",
            labels=1,
        )


def test_overly_precise_timestamps():
    ap = stix2.v20.AttackPattern(
        id=ATTACK_PATTERN_ID,
        created="2016-05-12T08:17:27.0000342Z",
        modified="2016-05-12T08:17:27.000287Z",
        name="Spear Phishing",
        external_references=[{
            "source_name": "capec",
            "external_id": "CAPEC-163",
        }],
        description="...",
    )

    assert str(ap) == EXPECTED


def test_less_precise_timestamps():
    ap = stix2.v20.AttackPattern(
        id=ATTACK_PATTERN_ID,
        created="2016-05-12T08:17:27.00Z",
        modified="2016-05-12T08:17:27.0Z",
        name="Spear Phishing",
        external_references=[{
            "source_name": "capec",
            "external_id": "CAPEC-163",
        }],
        description="...",
    )

    assert str(ap) == EXPECTED

# TODO: Add other examples
