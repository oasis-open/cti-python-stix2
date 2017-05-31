import datetime as dt

import pytest
import pytz

import stix2

from .constants import ATTACK_PATTERN_ID


EXPECTED = """{
    "created": "2016-05-12T08:17:27Z",
    "description": "...",
    "external_references": [
        {
            "external_id": "CAPEC-163",
            "source_name": "capec"
        }
    ],
    "id": "attack-pattern--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061",
    "modified": "2016-05-12T08:17:27Z",
    "name": "Spear Phishing",
    "type": "attack-pattern"
}"""


def test_attack_pattern_example():
    ap = stix2.AttackPattern(
        id="attack-pattern--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061",
        created="2016-05-12T08:17:27Z",
        modified="2016-05-12T08:17:27Z",
        name="Spear Phishing",
        external_references=[{
            "source_name": "capec",
            "external_id": "CAPEC-163"
        }],
        description="...",
    )

    assert str(ap) == EXPECTED


@pytest.mark.parametrize("data", [
    EXPECTED,
    {
        "type": "attack-pattern",
        "id": "attack-pattern--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061",
        "created": "2016-05-12T08:17:27Z",
        "modified": "2016-05-12T08:17:27Z",
        "description": "...",
        "external_references": [
            {
                "external_id": "CAPEC-163",
                "source_name": "capec"
            }
        ],
        "name": "Spear Phishing",
    },
])
def test_parse_attack_pattern(data):
    ap = stix2.parse(data)

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
        stix2.AttackPattern(
            id="attack-pattern--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061",
            created="2016-05-12T08:17:27Z",
            modified="2016-05-12T08:17:27Z",
            name="Spear Phishing",
            labels=1
        )

# TODO: Add other examples
