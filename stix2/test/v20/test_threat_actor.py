import datetime as dt

import pytest
import pytz

import stix2

from .constants import IDENTITY_ID, THREAT_ACTOR_ID

EXPECTED = """{
    "type": "threat-actor",
    "id": "threat-actor--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
    "created_by_ref": "identity--311b2d2d-f010-4473-83ec-1edf84858f4c",
    "created": "2016-04-06T20:03:48.000Z",
    "modified": "2016-04-06T20:03:48.000Z",
    "name": "Evil Org",
    "description": "The Evil Org threat actor group",
    "labels": [
        "crime-syndicate"
    ]
}"""


def test_threat_actor_example():
    threat_actor = stix2.v20.ThreatActor(
        id=THREAT_ACTOR_ID,
        created_by_ref=IDENTITY_ID,
        created="2016-04-06T20:03:48.000Z",
        modified="2016-04-06T20:03:48.000Z",
        description="The Evil Org threat actor group",
        labels=["crime-syndicate"],
        name="Evil Org",
    )

    assert str(threat_actor) == EXPECTED


@pytest.mark.parametrize(
    "data", [
        EXPECTED,
        {
            "created": "2016-04-06T20:03:48.000Z",
            "created_by_ref": IDENTITY_ID,
            "description": "The Evil Org threat actor group",
            "id": THREAT_ACTOR_ID,
            "modified": "2016-04-06T20:03:48.000Z",
            "labels": ["crime-syndicate"],
            "name": "Evil Org",
            "type": "threat-actor",
        },
    ],
)
def test_parse_threat_actor(data):
    actor = stix2.parse(data, version="2.0")

    assert actor.type == 'threat-actor'
    assert actor.id == THREAT_ACTOR_ID
    assert actor.created == dt.datetime(2016, 4, 6, 20, 3, 48, tzinfo=pytz.utc)
    assert actor.modified == dt.datetime(2016, 4, 6, 20, 3, 48, tzinfo=pytz.utc)
    assert actor.created_by_ref == IDENTITY_ID
    assert actor.description == "The Evil Org threat actor group"
    assert actor.name == "Evil Org"
    assert actor.labels == ["crime-syndicate"]

# TODO: Add other examples
