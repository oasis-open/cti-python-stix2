import datetime as dt

import pytest
import pytz

import stix2

from .constants import INTRUSION_SET_ID


EXPECTED = """{
    "type": "intrusion-set",
    "id": "intrusion-set--4e78f46f-a023-4e5f-bc24-71b3ca22ec29",
    "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
    "created": "2016-04-06T20:03:48.000Z",
    "modified": "2016-04-06T20:03:48.000Z",
    "name": "Bobcat Breakin",
    "description": "Incidents usually feature a shared TTP of a bobcat being released...",
    "aliases": [
        "Zookeeper"
    ],
    "goals": [
        "acquisition-theft",
        "harassment",
        "damage"
    ]
}"""


def test_intrusion_set_example():
    intrusion_set = stix2.IntrusionSet(
        id="intrusion-set--4e78f46f-a023-4e5f-bc24-71b3ca22ec29",
        created_by_ref="identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        created="2016-04-06T20:03:48.000Z",
        modified="2016-04-06T20:03:48.000Z",
        name="Bobcat Breakin",
        description="Incidents usually feature a shared TTP of a bobcat being released...",
        aliases=["Zookeeper"],
        goals=["acquisition-theft", "harassment", "damage"]
    )

    assert str(intrusion_set) == EXPECTED


@pytest.mark.parametrize("data", [
    EXPECTED,
    {
        "aliases": [
            "Zookeeper"
        ],
        "created": "2016-04-06T20:03:48.000Z",
        "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        "description": "Incidents usually feature a shared TTP of a bobcat being released...",
        "goals": [
            "acquisition-theft",
            "harassment",
            "damage"
        ],
        "id": "intrusion-set--4e78f46f-a023-4e5f-bc24-71b3ca22ec29",
        "modified": "2016-04-06T20:03:48.000Z",
        "name": "Bobcat Breakin",
        "type": "intrusion-set"
    },
])
def test_parse_intrusion_set(data):
    intset = stix2.parse(data)

    assert intset.type == "intrusion-set"
    assert intset.id == INTRUSION_SET_ID
    assert intset.created == dt.datetime(2016, 4, 6, 20, 3, 48, tzinfo=pytz.utc)
    assert intset.modified == dt.datetime(2016, 4, 6, 20, 3, 48, tzinfo=pytz.utc)
    assert intset.goals == ["acquisition-theft", "harassment", "damage"]
    assert intset.aliases == ["Zookeeper"]
    assert intset.description == "Incidents usually feature a shared TTP of a bobcat being released..."
    assert intset.name == "Bobcat Breakin"

# TODO: Add other examples
