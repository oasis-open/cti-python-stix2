import stix2

EXPECTED = """{
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

# TODO: Add other examples
