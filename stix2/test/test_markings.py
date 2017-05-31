import datetime as dt

import pytest
import pytz

import stix2
from stix2.other import TLP_WHITE

from .constants import MARKING_DEFINITION_ID


EXPECTED_TLP_MARKING_DEFINITION = """{
    "created": "2017-01-20T00:00:00Z",
    "definition": {
        "tlp": "white"
    },
    "definition_type": "tlp",
    "id": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "type": "marking-definition"
}"""

EXPECTED_STATEMENT_MARKING_DEFINITION = """{
    "created": "2017-01-20T00:00:00Z",
    "definition": {
        "statement": "Copyright 2016, Example Corp"
    },
    "definition_type": "statement",
    "id": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "type": "marking-definition"
}"""

EXPECTED_GRANULAR_MARKING = """{
    "marking_ref": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "selectors": [
        "abc",
        "abc.[23]",
        "abc.def",
        "abc.[2].efg"
    ]
}"""

EXPECTED_CAMPAIGN_WITH_GRANULAR_MARKINGS = """{
    "created": "2016-04-06T20:03:00Z",
    "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
    "description": "Campaign by Green Group against a series of targets in the financial services sector.",
    "granular_markings": [
        {
            "marking_ref": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
            "selectors": [
                "description"
            ]
        }
    ],
    "id": "campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
    "modified": "2016-04-06T20:03:00Z",
    "name": "Green Group Attacks Against Finance",
    "type": "campaign"
}"""


def test_marking_def_example_with_tlp():
    assert str(TLP_WHITE) == EXPECTED_TLP_MARKING_DEFINITION


def test_marking_def_example_with_statement():
    marking_definition = stix2.MarkingDefinition(
        id="marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
        created="2017-01-20T00:00:00.000Z",
        definition_type="statement",
        definition=stix2.StatementMarking(statement="Copyright 2016, Example Corp")
    )

    assert str(marking_definition) == EXPECTED_STATEMENT_MARKING_DEFINITION


def test_marking_def_example_with_positional_statement():
    marking_definition = stix2.MarkingDefinition(
        id="marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
        created="2017-01-20T00:00:00.000Z",
        definition_type="statement",
        definition=stix2.StatementMarking("Copyright 2016, Example Corp")
    )

    assert str(marking_definition) == EXPECTED_STATEMENT_MARKING_DEFINITION


def test_granular_example():
    granular_marking = stix2.GranularMarking(
        marking_ref="marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
        selectors=["abc", "abc.[23]", "abc.def", "abc.[2].efg"]
    )

    assert str(granular_marking) == EXPECTED_GRANULAR_MARKING


def test_granular_example_with_bad_selector():
    with pytest.raises(stix2.exceptions.InvalidValueError) as excinfo:
        stix2.GranularMarking(
            marking_ref="marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
            selectors=["abc[0]"]   # missing "."
        )

    assert excinfo.value.cls == stix2.GranularMarking
    assert excinfo.value.prop_name == "selectors"
    assert excinfo.value.reason == "must adhere to selector syntax."
    assert str(excinfo.value) == "Invalid value for GranularMarking 'selectors': must adhere to selector syntax."


def test_campaign_with_granular_markings_example():
    campaign = stix2.Campaign(
        id="campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
        created_by_ref="identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        created="2016-04-06T20:03:00Z",
        modified="2016-04-06T20:03:00Z",
        name="Green Group Attacks Against Finance",
        description="Campaign by Green Group against a series of targets in the financial services sector.",
        granular_markings=[
            stix2.GranularMarking(
                marking_ref="marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
                selectors=["description"])
            ])
    print(str(campaign))
    assert str(campaign) == EXPECTED_CAMPAIGN_WITH_GRANULAR_MARKINGS


@pytest.mark.parametrize("data", [
    EXPECTED_TLP_MARKING_DEFINITION,
    {
        "id": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
        "type": "marking-definition",
        "created": "2017-01-20T00:00:00Z",
        "definition": {
            "tlp": "white"
        },
        "definition_type": "tlp",
    },
])
def test_parse_marking_definition(data):
    gm = stix2.parse(data)

    assert gm.type == 'marking-definition'
    assert gm.id == MARKING_DEFINITION_ID
    assert gm.created == dt.datetime(2017, 1, 20, 0, 0, 0, tzinfo=pytz.utc)
    assert gm.definition.tlp == "white"
    assert gm.definition_type == "tlp"


# TODO: Add other examples
