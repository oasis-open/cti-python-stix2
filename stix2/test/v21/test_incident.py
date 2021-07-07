import datetime as dt

import pytest
import pytz

import stix2

from .constants import INCIDENT_ID

EXPECTED = """{
    "type": "incident",
    "spec_version": "2.1",
    "id": "incident--40fc3b35-0dc4-4afd-9927-288d44bfce20",
    "created": "2015-12-21T19:59:11.000Z",
    "modified": "2015-12-21T19:59:11.000Z",
    "name": "Breach of Cyber Tech Dynamics",
    "description": "Intrusion into enterprise network"
}"""


def test_incident_example():
    incident = stix2.v21.Incident(
        id=INCIDENT_ID,
        created="2015-12-21T19:59:11.000Z",
        modified="2015-12-21T19:59:11.000Z",
        name="Breach of Cyber Tech Dynamics",
        description="Intrusion into enterprise network",
    )

    assert incident.serialize(pretty=True) == EXPECTED


@pytest.mark.parametrize(
    "data", [
        EXPECTED,
        {
            "created": "2015-12-21T19:59:11.000Z",
            "id": INCIDENT_ID,
            "description": "Intrusion into enterprise network",
            "modified": "2015-12-21T19:59:11.000Z",
            "name": "Breach of Cyber Tech Dynamics",
            "spec_version": "2.1",
            "type": "incident",
        },
    ],
)
def test_parse_incident(data):
    incident = stix2.parse(data, version="2.1")

    assert incident.type == 'incident'
    assert incident.spec_version == '2.1'
    assert incident.id == INCIDENT_ID
    assert incident.created == dt.datetime(2015, 12, 21, 19, 59, 11, tzinfo=pytz.utc)
    assert incident.modified == dt.datetime(2015, 12, 21, 19, 59, 11, tzinfo=pytz.utc)
    assert incident.name == 'Breach of Cyber Tech Dynamics'
    assert incident.description == 'Intrusion into enterprise network'


def test_parse_no_type():
    with pytest.raises(stix2.exceptions.ParseError):
        stix2.parse(
            """
        {
            "id": "incident--40fc3b35-0dc4-4afd-9927-288d44bfce20",
            "created": "2015-12-21T19:59:11.000Z",
            "modified": "2015-12-21T19:59:11.000Z",
            "name": "Breach of Cyber Tech Dynamics",
            "description": "Intrusion into enterprise network"
        }""", version="2.1",
        )


def test_incident_with_custom():
    incident = stix2.v21.Incident(
        name="Breach of Cyber Tech Dynamics",
        description="Intrusion into enterprise network",
        custom_properties={'x_foo': 'bar'},
    )

    assert incident.x_foo == "bar"
