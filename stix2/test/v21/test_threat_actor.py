import datetime as dt

import pytest
import pytz

import stix2
import stix2.v21

from .constants import IDENTITY_ID, THREAT_ACTOR_ID

EXPECTED = """{
    "type": "threat-actor",
    "spec_version": "2.1",
    "id": "threat-actor--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
    "created_by_ref": "identity--311b2d2d-f010-4473-83ec-1edf84858f4c",
    "created": "2016-04-06T20:03:48.000Z",
    "modified": "2016-04-06T20:03:48.000Z",
    "name": "Evil Org",
    "description": "The Evil Org threat actor group",
    "threat_actor_types": [
        "crime-syndicate"
    ]
}"""


def test_threat_actor_example():
    threat_actor = stix2.v21.ThreatActor(
        id=THREAT_ACTOR_ID,
        created_by_ref=IDENTITY_ID,
        created="2016-04-06T20:03:48.000Z",
        modified="2016-04-06T20:03:48.000Z",
        name="Evil Org",
        description="The Evil Org threat actor group",
        threat_actor_types=["crime-syndicate"],
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
            "threat_actor_types": [
                "crime-syndicate",
            ],
            "modified": "2016-04-06T20:03:48.000Z",
            "name": "Evil Org",
            "spec_version": "2.1",
            "type": "threat-actor",
        },
    ],
)
def test_parse_threat_actor(data):
    actor = stix2.parse(data, version="2.1")

    assert actor.type == 'threat-actor'
    assert actor.spec_version == '2.1'
    assert actor.id == THREAT_ACTOR_ID
    assert actor.created == dt.datetime(2016, 4, 6, 20, 3, 48, tzinfo=pytz.utc)
    assert actor.modified == dt.datetime(2016, 4, 6, 20, 3, 48, tzinfo=pytz.utc)
    assert actor.created_by_ref == IDENTITY_ID
    assert actor.description == "The Evil Org threat actor group"
    assert actor.name == "Evil Org"
    assert actor.threat_actor_types == ["crime-syndicate"]


def test_seen_ordering_constraint():
    """
    Test first_seen/last_seen value co-constraint.
    """
    with pytest.raises(ValueError):
        stix2.v21.ThreatActor(
            name="Bad Person",
            threat_actor_types=["bad person", "evil person"],
            first_seen="2010-04-21T09:31:11Z",
            last_seen="2009-02-06T03:39:31Z",
        )

    # equal timestamps is okay.
    stix2.v21.ThreatActor(
        name="Bad Person",
        threat_actor_types=["bad person", "evil person"],
        first_seen="2010-04-21T09:31:11Z",
        last_seen="2010-04-21T09:31:11Z",
    )


# TODO: Add other examples
