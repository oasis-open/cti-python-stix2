import datetime as dt

import pytest
import pytz

import stix2

from .constants import TOOL_ID


EXPECTED = """{
    "type": "tool",
    "id": "tool--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
    "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
    "created": "2016-04-06T20:03:48.000Z",
    "modified": "2016-04-06T20:03:48.000Z",
    "name": "VNC",
    "labels": [
        "remote-access"
    ]
}"""


def test_tool_example():
    tool = stix2.Tool(
        id="tool--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
        created_by_ref="identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        created="2016-04-06T20:03:48.000Z",
        modified="2016-04-06T20:03:48.000Z",
        name="VNC",
        labels=["remote-access"],
    )

    assert str(tool) == EXPECTED


@pytest.mark.parametrize("data", [
    EXPECTED,
    {
        "created": "2016-04-06T20:03:48Z",
        "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        "id": "tool--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
        "labels": [
            "remote-access"
        ],
        "modified": "2016-04-06T20:03:48Z",
        "name": "VNC",
        "type": "tool"
    },
])
def test_parse_tool(data):
    tool = stix2.parse(data)

    assert tool.type == 'tool'
    assert tool.id == TOOL_ID
    assert tool.created == dt.datetime(2016, 4, 6, 20, 3, 48, tzinfo=pytz.utc)
    assert tool.modified == dt.datetime(2016, 4, 6, 20, 3, 48, tzinfo=pytz.utc)
    assert tool.created_by_ref == "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff"
    assert tool.labels == ["remote-access"]
    assert tool.name == "VNC"

# TODO: Add other examples
