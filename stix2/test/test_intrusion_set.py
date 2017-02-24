import stix2

EXPECTED = """{
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

# TODO: Add other examples
