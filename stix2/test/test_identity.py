import stix2

EXPECTED = """{
    "created": "2015-12-21T19:59:11.000Z",
    "id": "identity--311b2d2d-f010-5473-83ec-1edf84858f4c",
    "identity_class": "individual",
    "modified": "2015-12-21T19:59:11.000Z",
    "name": "John Smith",
    "type": "identity"
}"""


def test_identity_example():
    report = stix2.Identity(
        id="identity--311b2d2d-f010-5473-83ec-1edf84858f4c",
        created="2015-12-21T19:59:11.000Z",
        modified="2015-12-21T19:59:11.000Z",
        name="John Smith",
        identity_class="individual",
    )

    assert str(report) == EXPECTED

# TODO: Add other examples
