import datetime as dt

import pytest
import pytz

import stix2
from stix2.v21 import TLP_WHITE

from .constants import IDENTITY_ID, MARKING_DEFINITION_ID

EXPECTED_TLP_MARKING_DEFINITION = """{
    "type": "marking-definition",
    "spec_version": "2.1",
    "id": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "created": "2017-01-20T00:00:00.000Z",
    "definition_type": "tlp",
    "definition": {
        "tlp": "white"
    }
}"""

EXPECTED_STATEMENT_MARKING_DEFINITION = """{
    "type": "marking-definition",
    "spec_version": "2.1",
    "id": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "created": "2017-01-20T00:00:00Z",
    "definition_type": "statement",
    "definition": {
        "statement": "Copyright 2016, Example Corp"
    }
}"""

EXPECTED_CAMPAIGN_WITH_OBJECT_MARKING = """{
    "type": "campaign",
    "spec_version": "2.1",
    "id": "campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
    "created_by_ref": "identity--311b2d2d-f010-4473-83ec-1edf84858f4c",
    "created": "2016-04-06T20:03:00.000Z",
    "modified": "2016-04-06T20:03:00.000Z",
    "name": "Green Group Attacks Against Finance",
    "description": "Campaign by Green Group against a series of targets in the financial services sector.",
    "object_marking_refs": [
        "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
    ]
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
    "type": "campaign",
    "spec_version": "2.1",
    "id": "campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
    "created_by_ref": "identity--311b2d2d-f010-4473-83ec-1edf84858f4c",
    "created": "2016-04-06T20:03:00.000Z",
    "modified": "2016-04-06T20:03:00.000Z",
    "name": "Green Group Attacks Against Finance",
    "description": "Campaign by Green Group against a series of targets in the financial services sector.",
    "granular_markings": [
        {
            "marking_ref": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
            "selectors": [
                "description"
            ]
        }
    ]
}"""


def test_marking_def_example_with_tlp():
    assert str(TLP_WHITE) == EXPECTED_TLP_MARKING_DEFINITION


def test_marking_def_example_with_statement_positional_argument():
    marking_definition = stix2.v21.MarkingDefinition(
        id=MARKING_DEFINITION_ID,
        created="2017-01-20T00:00:00.000Z",
        definition_type="statement",
        definition=stix2.StatementMarking(statement="Copyright 2016, Example Corp"),
    )

    assert str(marking_definition) == EXPECTED_STATEMENT_MARKING_DEFINITION


def test_marking_def_example_with_kwargs_statement():
    kwargs = dict(statement="Copyright 2016, Example Corp")
    marking_definition = stix2.v21.MarkingDefinition(
        id=MARKING_DEFINITION_ID,
        created="2017-01-20T00:00:00.000Z",
        definition_type="statement",
        definition=stix2.StatementMarking(**kwargs),
    )

    assert str(marking_definition) == EXPECTED_STATEMENT_MARKING_DEFINITION


def test_marking_def_invalid_type():
    with pytest.raises(ValueError):
        stix2.v21.MarkingDefinition(
            id=MARKING_DEFINITION_ID,
            created="2017-01-20T00:00:00.000Z",
            definition_type="my-definition-type",
            definition=stix2.StatementMarking("Copyright 2016, Example Corp"),
        )


def test_campaign_with_markings_example():
    campaign = stix2.v21.Campaign(
        id="campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
        created_by_ref=IDENTITY_ID,
        created="2016-04-06T20:03:00Z",
        modified="2016-04-06T20:03:00Z",
        name="Green Group Attacks Against Finance",
        description="Campaign by Green Group against a series of targets in the financial services sector.",
        object_marking_refs=TLP_WHITE,
    )
    assert str(campaign) == EXPECTED_CAMPAIGN_WITH_OBJECT_MARKING


def test_granular_example():
    granular_marking = stix2.v21.GranularMarking(
        marking_ref=MARKING_DEFINITION_ID,
        selectors=["abc", "abc.[23]", "abc.def", "abc.[2].efg"],
    )

    assert str(granular_marking) == EXPECTED_GRANULAR_MARKING


def test_granular_example_with_bad_selector():
    with pytest.raises(stix2.exceptions.InvalidValueError) as excinfo:
        stix2.v21.GranularMarking(
            marking_ref=MARKING_DEFINITION_ID,
            selectors=["abc[0]"],   # missing "."
        )

    assert excinfo.value.cls == stix2.v21.GranularMarking
    assert excinfo.value.prop_name == "selectors"
    assert excinfo.value.reason == "must adhere to selector syntax."
    assert str(excinfo.value) == "Invalid value for GranularMarking 'selectors': must adhere to selector syntax."


def test_campaign_with_granular_markings_example():
    campaign = stix2.v21.Campaign(
        id="campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
        created_by_ref=IDENTITY_ID,
        created="2016-04-06T20:03:00Z",
        modified="2016-04-06T20:03:00Z",
        name="Green Group Attacks Against Finance",
        description="Campaign by Green Group against a series of targets in the financial services sector.",
        granular_markings=[
            stix2.v21.GranularMarking(
                marking_ref=MARKING_DEFINITION_ID,
                selectors=["description"],
            ),
        ],
    )
    assert str(campaign) == EXPECTED_CAMPAIGN_WITH_GRANULAR_MARKINGS


@pytest.mark.parametrize(
    "data", [
        EXPECTED_TLP_MARKING_DEFINITION,
        {
            "id": MARKING_DEFINITION_ID,
            "spec_version": "2.1",
            "type": "marking-definition",
            "created": "2017-01-20T00:00:00Z",
            "definition": {
                "tlp": "white",
            },
            "definition_type": "tlp",
        },
    ],
)
def test_parse_marking_definition(data):
    gm = stix2.parse(data, version="2.1")

    assert gm.type == 'marking-definition'
    assert gm.spec_version == '2.1'
    assert gm.id == MARKING_DEFINITION_ID
    assert gm.created == dt.datetime(2017, 1, 20, 0, 0, 0, tzinfo=pytz.utc)
    assert gm.definition.tlp == "white"
    assert gm.definition_type == "tlp"


@stix2.v21.CustomMarking(
    'x-new-marking-type', [
        ('property1', stix2.properties.StringProperty(required=True)),
        ('property2', stix2.properties.IntegerProperty()),
    ],
)
class NewMarking(object):
    def __init__(self, property2=None, **kwargs):
        if "property3" in kwargs and not isinstance(kwargs.get("property3"), int):
            raise TypeError("Must be integer!")


def test_registered_custom_marking():
    nm = NewMarking(property1='something', property2=55)

    marking_def = stix2.v21.MarkingDefinition(
        id="marking-definition--00000000-0000-4000-8000-000000000012",
        created="2017-01-22T00:00:00.000Z",
        definition_type="x-new-marking-type",
        definition=nm,
    )

    assert marking_def.type == "marking-definition"
    assert marking_def.id == "marking-definition--00000000-0000-4000-8000-000000000012"
    assert marking_def.created == dt.datetime(2017, 1, 22, 0, 0, 0, tzinfo=pytz.utc)
    assert marking_def.definition.property1 == "something"
    assert marking_def.definition.property2 == 55
    assert marking_def.definition_type == "x-new-marking-type"


def test_registered_custom_marking_raises_exception():
    with pytest.raises(TypeError) as excinfo:
        NewMarking(property1='something', property3='something', allow_custom=True)

    assert str(excinfo.value) == "Must be integer!"


def test_not_registered_marking_raises_exception():
    with pytest.raises(ValueError) as excinfo:
        # Used custom object on purpose to demonstrate a not-registered marking
        @stix2.v21.CustomObject(
            'x-new-marking-type2', [
                ('property1', stix2.properties.StringProperty(required=True)),
                ('property2', stix2.properties.IntegerProperty()),
            ],
        )
        class NewObject2(object):
            def __init__(self, property2=None, **kwargs):
                return

        no = NewObject2(property1='something', property2=55)

        stix2.v21.MarkingDefinition(
            id="marking-definition--00000000-0000-4000-8000-000000000012",
            created="2017-01-22T00:00:00.000Z",
            definition_type="x-new-marking-type2",
            definition=no,
        )

    assert str(excinfo.value) == "definition_type must be a valid marking type"


def test_marking_wrong_type_construction():
    with pytest.raises(ValueError) as excinfo:
        # Test passing wrong type for properties.
        @stix2.v21.CustomMarking('x-new-marking-type2', ("a", "b"))
        class NewObject3(object):
            pass

    assert str(excinfo.value) == "Must supply a list, containing tuples. For example, [('property1', IntegerProperty())]"


def test_campaign_add_markings():
    campaign = stix2.v21.Campaign(
        id="campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
        created_by_ref=IDENTITY_ID,
        created="2016-04-06T20:03:00Z",
        modified="2016-04-06T20:03:00Z",
        name="Green Group Attacks Against Finance",
        description="Campaign by Green Group against a series of targets in the financial services sector.",
    )
    campaign = campaign.add_markings(TLP_WHITE)
    assert campaign.object_marking_refs[0] == TLP_WHITE.id
