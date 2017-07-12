import pytest

import stix2


def test_identity_custom_property():
    with pytest.raises(ValueError):
        stix2.Identity(
            id="identity--311b2d2d-f010-5473-83ec-1edf84858f4c",
            created="2015-12-21T19:59:11Z",
            modified="2015-12-21T19:59:11Z",
            name="John Smith",
            identity_class="individual",
            custom_properties="foobar",
        )

    identity = stix2.Identity(
        id="identity--311b2d2d-f010-5473-83ec-1edf84858f4c",
        created="2015-12-21T19:59:11Z",
        modified="2015-12-21T19:59:11Z",
        name="John Smith",
        identity_class="individual",
        custom_properties={
            "foo": "bar",
        },
    )

    assert identity.foo == "bar"


def test_identity_custom_property_invalid():
    with pytest.raises(stix2.exceptions.ExtraPropertiesError):
        stix2.Identity(
            id="identity--311b2d2d-f010-5473-83ec-1edf84858f4c",
            created="2015-12-21T19:59:11Z",
            modified="2015-12-21T19:59:11Z",
            name="John Smith",
            identity_class="individual",
            x_foo="bar",
        )


def test_identity_custom_property_allowed():
    identity = stix2.Identity(
        id="identity--311b2d2d-f010-5473-83ec-1edf84858f4c",
        created="2015-12-21T19:59:11Z",
        modified="2015-12-21T19:59:11Z",
        name="John Smith",
        identity_class="individual",
        x_foo="bar",
        allow_custom=True,
    )
    assert identity.x_foo == "bar"


@pytest.mark.parametrize("data", [
    """{
        "type": "identity",
        "id": "identity--311b2d2d-f010-5473-83ec-1edf84858f4c",
        "created": "2015-12-21T19:59:11Z",
        "modified": "2015-12-21T19:59:11Z",
        "name": "John Smith",
        "identity_class": "individual",
        "foo": "bar"
    }""",
])
def test_parse_identity_custom_property(data):
    with pytest.raises(stix2.exceptions.ExtraPropertiesError):
        identity = stix2.parse(data)

    identity = stix2.parse(data, allow_custom=True)
    assert identity.foo == "bar"


@stix2.sdo.CustomObject('x-new-type', {
    'property1': stix2.properties.StringProperty(required=True),
    'property2': stix2.properties.IntegerProperty(),
})
class NewType():
    def __init__(self, property2=None, **kwargs):
        if property2 and property2 < 10:
            raise ValueError("'property2' is too small.")


def test_custom_object_type():
    nt = NewType(property1='something')
    assert nt.property1 == 'something'

    with pytest.raises(stix2.exceptions.MissingPropertiesError):
        NewType(property2=42)

    with pytest.raises(ValueError):
        NewType(property1='something', property2=4)


def test_parse_custom_object_type():
    nt_string = """{
        "type": "x-new-type",
        "created": "2015-12-21T19:59:11Z",
        "property1": "something"
    }"""

    nt = stix2.parse(nt_string)
    assert nt.property1 == 'something'


@stix2.observables.CustomObservable('x-new-observable', {
    'property1': stix2.properties.StringProperty(required=True),
    'property2': stix2.properties.IntegerProperty(),
})
class NewObservable():
    def __init__(self, property2=None, **kwargs):
        if property2 and property2 < 10:
            raise ValueError("'property2' is too small.")


def test_custom_observable_object():
    no = NewObservable(property1='something')
    assert no.property1 == 'something'

    with pytest.raises(stix2.exceptions.MissingPropertiesError):
        NewObservable(property2=42)

    with pytest.raises(ValueError):
        NewObservable(property1='something', property2=4)


def test_parse_custom_observable_object():
    nt_string = """{
        "type": "x-new-observable",
        "property1": "something"
    }"""

    nt = stix2.parse_observable(nt_string)
    assert nt.property1 == 'something'


def test_observable_custom_property():
    with pytest.raises(ValueError):
        NewObservable(
            property1='something',
            custom_properties="foobar",
        )

    no = NewObservable(
        property1='something',
        custom_properties={
            "foo": "bar",
        },
    )
    assert no.foo == "bar"


def test_observable_custom_property_invalid():
    with pytest.raises(stix2.exceptions.ExtraPropertiesError):
        NewObservable(
            property1='something',
            x_foo="bar",
        )


def test_observable_custom_property_allowed():
    no = NewObservable(
        property1='something',
        x_foo="bar",
        allow_custom=True,
    )
    assert no.x_foo == "bar"
