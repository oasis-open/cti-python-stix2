import datetime as dt

import pytest
import pytz

import stix2

from .constants import EXTENSION_DEFINITION_IDS

EXPECTED = f"""{{
    "type": "extension-definition",
    "spec_version": "2.1",
    "id": "{EXTENSION_DEFINITION_IDS[0]}",
    "created_by_ref": "identity--11b76a96-5d2b-45e0-8a5a-f6994f370731",
    "created": "2014-02-20T09:16:08.000Z",
    "modified": "2014-02-20T09:16:08.000Z",
    "name": "New SDO 1",
    "description": "This schema creates a new object type called my-favorite-sdo-1",
    "schema": "https://www.example.com/schema-my-favorite-sdo-1/v1/",
    "version": "1.2.1",
    "extension_types": [
        "new-sdo"
    ]
}}"""


def test_extension_definition_example():
    extension_definition = stix2.v21.ExtensionDefinition(
        id=EXTENSION_DEFINITION_IDS[0],
        created_by_ref="identity--11b76a96-5d2b-45e0-8a5a-f6994f370731",
        created="2014-02-20T09:16:08.000Z",
        modified="2014-02-20T09:16:08.000Z",
        name="New SDO 1",
        description="This schema creates a new object type called my-favorite-sdo-1",
        schema="https://www.example.com/schema-my-favorite-sdo-1/v1/",
        version="1.2.1",
        extension_types=["new-sdo"],
    )

    assert extension_definition.serialize(pretty=True) == EXPECTED


@pytest.mark.parametrize(
    "data", [
        EXPECTED,
        {
            "id": f"{EXTENSION_DEFINITION_IDS[0]}",
            "type": "extension-definition",
            "spec_version": "2.1",
            "created_by_ref": "identity--11b76a96-5d2b-45e0-8a5a-f6994f370731",
            "created": "2014-02-20T09:16:08.000Z",
            "modified": "2014-02-20T09:16:08.000Z",
            "name": "New SDO 1",
            "description": "This schema creates a new object type called my-favorite-sdo-1",
            "schema": "https://www.example.com/schema-my-favorite-sdo-1/v1/",
            "version": "1.2.1",
            "extension_types": ["new-sdo"],
        },
    ],
)
def test_parse_extension_definition(data):
    extension_definition = stix2.parse(data, version="2.1")

    assert extension_definition.type == 'extension-definition'
    assert extension_definition.spec_version == '2.1'
    assert extension_definition.id == EXTENSION_DEFINITION_IDS[0]
    assert extension_definition.created == dt.datetime(2014, 2, 20, 9, 16, 8, tzinfo=pytz.utc)
    assert extension_definition.modified == dt.datetime(2014, 2, 20, 9, 16, 8, tzinfo=pytz.utc)
    assert extension_definition.name == 'New SDO 1'
    assert extension_definition.description == 'This schema creates a new object type called my-favorite-sdo-1'
    assert extension_definition.schema == 'https://www.example.com/schema-my-favorite-sdo-1/v1/'
    assert extension_definition.version == '1.2.1'
    assert extension_definition.extension_types == ['new-sdo']


def test_parse_no_type():
    with pytest.raises(stix2.exceptions.ParseError):
        stix2.parse(
            """{
            "id": "{EXTENSION_DEFINITION_IDS[0]}",
            "spec_version": "2.1",
            "name": "New SDO 1",
            "description": "This schema creates a new object type called my-favorite-sdo-1",
            "created": "2014-02-20T09:16:08.989000Z",
            "modified": "2014-02-20T09:16:08.989000Z",
            "created_by_ref": "identity--11b76a96-5d2b-45e0-8a5a-f6994f370731",
            "schema": "https://www.example.com/schema-my-favorite-sdo-1/v1/",
            "version": "1.2.1",
            "extension_types": [ "new-sdo" ]
        }""", version="2.1",
        )


def test_extension_definition_with_custom():
    extension_definition = stix2.v21.ExtensionDefinition(
        created_by_ref="identity--11b76a96-5d2b-45e0-8a5a-f6994f370731",
        created="2014-02-20T09:16:08.000Z",
        modified="2014-02-20T09:16:08.000Z",
        name="New SDO 1",
        description="This schema creates a new object type called my-favorite-sdo-1",
        schema="https://www.example.com/schema-my-favorite-sdo-1/v1/",
        version="1.2.1",
        extension_types=["new-sdo"],
        custom_properties={'x_foo': 'bar'},
    )

    assert extension_definition.x_foo == "bar"
