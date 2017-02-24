import stix2

EXPECTED = """{
    "created": "2016-05-12T08:17:27.000Z",
    "description": "...",
    "external_references": [
        {
            "id": "CAPEC-163",
            "source_name": "capec"
        }
    ],
    "id": "attack-pattern--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061",
    "modified": "2016-05-12T08:17:27.000Z",
    "name": "Spear Phishing",
    "type": "attack-pattern"
}"""


def test_attack_pattern_example():
    ap = stix2.AttackPattern(
        id="attack-pattern--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061",
        created="2016-05-12T08:17:27.000Z",
        modified="2016-05-12T08:17:27.000Z",
        name="Spear Phishing",
        external_references=[{
            "source_name": "capec",
            "id": "CAPEC-163"
        }],
        description="...",
    )

    assert str(ap) == EXPECTED


# TODO: Add other examples
