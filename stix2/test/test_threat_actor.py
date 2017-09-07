import datetime as dt

import pytest
import pytz

import stix2

from .constants import THREAT_ACTOR_ID


EXPECTED = """{
    "type": "threat-actor",
    "id": "threat-actor--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
    "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
    "created": "2016-04-06T20:03:48.000Z",
    "modified": "2016-04-06T20:03:48.000Z",
    "name": "Evil Org",
    "description": "The Evil Org threat actor group",
    "labels": [
        "crime-syndicate"
    ]
}"""


def test_threat_actor_example():
    threat_actor = stix2.ThreatActor(
        id="threat-actor--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
        created_by_ref="identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        created="2016-04-06T20:03:48.000Z",
        modified="2016-04-06T20:03:48.000Z",
        name="Evil Org",
        description="The Evil Org threat actor group",
        labels=["crime-syndicate"],
    )

    assert str(threat_actor) == EXPECTED


@pytest.mark.parametrize("data", [
    EXPECTED,
    {
        "created": "2016-04-06T20:03:48.000Z",
        "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        "description": "The Evil Org threat actor group",
        "id": "threat-actor--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
        "labels": [
            "crime-syndicate"
        ],
        "modified": "2016-04-06T20:03:48.000Z",
        "name": "Evil Org",
        "type": "threat-actor"
    },
])
def test_parse_threat_actor(data):
    actor = stix2.parse(data)

    assert actor.type == 'threat-actor'
    assert actor.id == THREAT_ACTOR_ID
    assert actor.created == dt.datetime(2016, 4, 6, 20, 3, 48, tzinfo=pytz.utc)
    assert actor.modified == dt.datetime(2016, 4, 6, 20, 3, 48, tzinfo=pytz.utc)
    assert actor.created_by_ref == "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff"
    assert actor.description == "The Evil Org threat actor group"
    assert actor.name == "Evil Org"
    assert actor.labels == ["crime-syndicate"]

# TODO: Add other examples
