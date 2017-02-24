import stix2

EXPECTED = """{
    "created": "2016-04-06T20:03:48.000Z",
    "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
    "id": "tool--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
    "labels": [
        "remote-access"
    ],
    "modified": "2016-04-06T20:03:48.000Z",
    "name": "VNC",
    "type": "tool"
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

# TODO: Add other examples
