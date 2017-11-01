import pytest

import stix2

from .constants import FAKE_TIME


def test_identity_custom_property():
    with pytest.raises(ValueError) as excinfo:
        stix2.Identity(
            id="identity--311b2d2d-f010-5473-83ec-1edf84858f4c",
            created="2015-12-21T19:59:11Z",
            modified="2015-12-21T19:59:11Z",
            name="John Smith",
            identity_class="individual",
            custom_properties="foobar",
        )
    assert str(excinfo.value) == "'custom_properties' must be a dictionary"

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
    with pytest.raises(stix2.exceptions.ExtraPropertiesError) as excinfo:
        stix2.Identity(
            id="identity--311b2d2d-f010-5473-83ec-1edf84858f4c",
            created="2015-12-21T19:59:11Z",
            modified="2015-12-21T19:59:11Z",
            name="John Smith",
            identity_class="individual",
            x_foo="bar",
        )
    assert excinfo.value.cls == stix2.Identity
    assert excinfo.value.properties == ['x_foo']
    assert "Unexpected properties for" in str(excinfo.value)


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
    with pytest.raises(stix2.exceptions.ExtraPropertiesError) as excinfo:
        identity = stix2.parse(data)
    assert excinfo.value.cls == stix2.Identity
    assert excinfo.value.properties == ['foo']
    assert "Unexpected properties for" in str(excinfo.value)

    identity = stix2.parse(data, allow_custom=True)
    assert identity.foo == "bar"


def test_custom_property_in_bundled_object():
    identity = stix2.Identity(
        name="John Smith",
        identity_class="individual",
        x_foo="bar",
        allow_custom=True,
    )
    bundle = stix2.Bundle(identity, allow_custom=True)

    assert bundle.objects[0].x_foo == "bar"
    assert '"x_foo": "bar"' in str(bundle)


@stix2.sdo.CustomObject('x-new-type', [
    ('property1', stix2.properties.StringProperty(required=True)),
    ('property2', stix2.properties.IntegerProperty()),
])
class NewType(object):
    def __init__(self, property2=None, **kwargs):
        if property2 and property2 < 10:
            raise ValueError("'property2' is too small.")


def test_custom_object_type():
    nt = NewType(property1='something')
    assert nt.property1 == 'something'

    with pytest.raises(stix2.exceptions.MissingPropertiesError) as excinfo:
        NewType(property2=42)
    assert "No values for required properties" in str(excinfo.value)

    with pytest.raises(ValueError) as excinfo:
        NewType(property1='something', property2=4)
    assert "'property2' is too small." in str(excinfo.value)


def test_custom_object_no_init():
    @stix2.sdo.CustomObject('x-new-obj', [
        ('property1', stix2.properties.StringProperty(required=True)),
    ])
    class NewObj():
        pass

    no = NewObj(property1='something')
    assert no.property1 == 'something'

    @stix2.sdo.CustomObject('x-new-obj2', [
        ('property1', stix2.properties.StringProperty(required=True)),
    ])
    class NewObj2(object):
        pass

    no2 = NewObj2(property1='something')
    assert no2.property1 == 'something'


def test_parse_custom_object_type():
    nt_string = """{
        "type": "x-new-type",
        "created": "2015-12-21T19:59:11Z",
        "property1": "something"
    }"""

    nt = stix2.parse(nt_string)
    assert nt.property1 == 'something'


def test_parse_unregistered_custom_object_type():
    nt_string = """{
        "type": "x-foobar-observable",
        "created": "2015-12-21T19:59:11Z",
        "property1": "something"
    }"""

    with pytest.raises(stix2.exceptions.ParseError) as excinfo:
        stix2.parse(nt_string)
    assert "Can't parse unknown object type" in str(excinfo.value)
    assert "use the CustomObject decorator." in str(excinfo.value)


@stix2.observables.CustomObservable('x-new-observable', [
    ('property1', stix2.properties.StringProperty(required=True)),
    ('property2', stix2.properties.IntegerProperty()),
    ('x_property3', stix2.properties.BooleanProperty()),
])
class NewObservable():
    def __init__(self, property2=None, **kwargs):
        if property2 and property2 < 10:
            raise ValueError("'property2' is too small.")


def test_custom_observable_object():
    no = NewObservable(property1='something')
    assert no.property1 == 'something'

    with pytest.raises(stix2.exceptions.MissingPropertiesError) as excinfo:
        NewObservable(property2=42)
    assert excinfo.value.properties == ['property1']
    assert "No values for required properties" in str(excinfo.value)

    with pytest.raises(ValueError) as excinfo:
        NewObservable(property1='something', property2=4)
    assert "'property2' is too small." in str(excinfo.value)


def test_custom_observable_object_no_init():
    @stix2.observables.CustomObservable('x-new-observable', [
        ('property1', stix2.properties.StringProperty()),
    ])
    class NewObs():
        pass

    no = NewObs(property1='something')
    assert no.property1 == 'something'

    @stix2.observables.CustomObservable('x-new-obs2', [
        ('property1', stix2.properties.StringProperty()),
    ])
    class NewObs2(object):
        pass

    no2 = NewObs2(property1='something')
    assert no2.property1 == 'something'


def test_custom_observable_object_invalid_ref_property():
    with pytest.raises(ValueError) as excinfo:
        @stix2.observables.CustomObservable('x-new-obs', [
            ('property_ref', stix2.properties.StringProperty()),
        ])
        class NewObs():
            pass
    assert "is named like an object reference property but is not an ObjectReferenceProperty" in str(excinfo.value)


def test_custom_observable_object_invalid_refs_property():
    with pytest.raises(ValueError) as excinfo:
        @stix2.observables.CustomObservable('x-new-obs', [
            ('property_refs', stix2.properties.StringProperty()),
        ])
        class NewObs():
            pass
    assert "is named like an object reference list property but is not a ListProperty containing ObjectReferenceProperty" in str(excinfo.value)


def test_custom_observable_object_invalid_refs_list_property():
    with pytest.raises(ValueError) as excinfo:
        @stix2.observables.CustomObservable('x-new-obs', [
            ('property_refs', stix2.properties.ListProperty(stix2.properties.StringProperty)),
        ])
        class NewObs():
            pass
    assert "is named like an object reference list property but is not a ListProperty containing ObjectReferenceProperty" in str(excinfo.value)


def test_custom_observable_object_invalid_valid_refs():
    @stix2.observables.CustomObservable('x-new-obs', [
        ('property1', stix2.properties.StringProperty(required=True)),
        ('property_ref', stix2.properties.ObjectReferenceProperty(valid_types='email-addr')),
    ])
    class NewObs():
        pass

    with pytest.raises(Exception) as excinfo:
        NewObs(_valid_refs=['1'],
               property1='something',
               property_ref='1')
    assert "must be created with _valid_refs as a dict, not a list" in str(excinfo.value)


def test_custom_no_properties_raises_exception():
    with pytest.raises(ValueError):

        @stix2.sdo.CustomObject('x-new-object-type')
        class NewObject1(object):
            pass


def test_custom_wrong_properties_arg_raises_exception():
    with pytest.raises(ValueError):

        @stix2.observables.CustomObservable('x-new-object-type', (("prop", stix2.properties.BooleanProperty())))
        class NewObject2(object):
            pass


def test_parse_custom_observable_object():
    nt_string = """{
        "type": "x-new-observable",
        "property1": "something"
    }"""

    nt = stix2.parse_observable(nt_string, [])
    assert nt.property1 == 'something'


def test_parse_unregistered_custom_observable_object():
    nt_string = """{
        "type": "x-foobar-observable",
        "property1": "something"
    }"""

    with pytest.raises(stix2.exceptions.ParseError) as excinfo:
        stix2.parse_observable(nt_string)
    assert "Can't parse unknown observable type" in str(excinfo.value)


def test_parse_invalid_custom_observable_object():
    nt_string = """{
        "property1": "something"
    }"""

    with pytest.raises(stix2.exceptions.ParseError) as excinfo:
        stix2.parse_observable(nt_string)
    assert "Can't parse observable with no 'type' property" in str(excinfo.value)


def test_observable_custom_property():
    with pytest.raises(ValueError) as excinfo:
        NewObservable(
            property1='something',
            custom_properties="foobar",
        )
    assert "'custom_properties' must be a dictionary" in str(excinfo.value)

    no = NewObservable(
        property1='something',
        custom_properties={
            "foo": "bar",
        },
    )
    assert no.foo == "bar"


def test_observable_custom_property_invalid():
    with pytest.raises(stix2.exceptions.ExtraPropertiesError) as excinfo:
        NewObservable(
            property1='something',
            x_foo="bar",
        )
    assert excinfo.value.properties == ['x_foo']
    assert "Unexpected properties for" in str(excinfo.value)


def test_observable_custom_property_allowed():
    no = NewObservable(
        property1='something',
        x_foo="bar",
        allow_custom=True,
    )
    assert no.x_foo == "bar"


def test_observed_data_with_custom_observable_object():
    no = NewObservable(property1='something')
    ob_data = stix2.ObservedData(
        first_observed=FAKE_TIME,
        last_observed=FAKE_TIME,
        number_observed=1,
        objects={'0': no},
        allow_custom=True,
    )
    assert ob_data.objects['0'].property1 == 'something'


@stix2.observables.CustomExtension(stix2.DomainName, 'x-new-ext', {
    'property1': stix2.properties.StringProperty(required=True),
    'property2': stix2.properties.IntegerProperty(),
})
class NewExtension():
    def __init__(self, property2=None, **kwargs):
        if property2 and property2 < 10:
            raise ValueError("'property2' is too small.")


def test_custom_extension():
    ext = NewExtension(property1='something')
    assert ext.property1 == 'something'

    with pytest.raises(stix2.exceptions.MissingPropertiesError) as excinfo:
        NewExtension(property2=42)
    assert excinfo.value.properties == ['property1']
    assert str(excinfo.value) == "No values for required properties for _Custom: (property1)."

    with pytest.raises(ValueError) as excinfo:
        NewExtension(property1='something', property2=4)
    assert str(excinfo.value) == "'property2' is too small."


def test_custom_extension_wrong_observable_type():
    ext = NewExtension(property1='something')
    with pytest.raises(ValueError) as excinfo:
        stix2.File(name="abc.txt",
                   extensions={
                       "ntfs-ext": ext,
                   })

    assert 'Cannot determine extension type' in excinfo.value.reason


def test_custom_extension_invalid_observable():
    # These extensions are being applied to improperly-created Observables.
    # The Observable classes should have been created with the CustomObservable decorator.
    class Foo(object):
        pass
    with pytest.raises(ValueError) as excinfo:
        @stix2.observables.CustomExtension(Foo, 'x-new-ext', {
            'property1': stix2.properties.StringProperty(required=True),
        })
        class FooExtension():
            pass  # pragma: no cover
    assert str(excinfo.value) == "'observable' must be a valid Observable class!"

    class Bar(stix2.observables._Observable):
        pass
    with pytest.raises(ValueError) as excinfo:
        @stix2.observables.CustomExtension(Bar, 'x-new-ext', {
            'property1': stix2.properties.StringProperty(required=True),
        })
        class BarExtension():
            pass
    assert "Unknown observable type" in str(excinfo.value)
    assert "Custom observables must be created with the @CustomObservable decorator." in str(excinfo.value)

    class Baz(stix2.observables._Observable):
        _type = 'Baz'
    with pytest.raises(ValueError) as excinfo:
        @stix2.observables.CustomExtension(Baz, 'x-new-ext', {
            'property1': stix2.properties.StringProperty(required=True),
        })
        class BazExtension():
            pass
    assert "Unknown observable type" in str(excinfo.value)
    assert "Custom observables must be created with the @CustomObservable decorator." in str(excinfo.value)


def test_custom_extension_no_properties():
    with pytest.raises(ValueError) as excinfo:
        @stix2.observables.CustomExtension(stix2.DomainName, 'x-new-ext2', None)
        class BarExtension():
            pass
    assert "'properties' must be a dict!" in str(excinfo.value)


def test_custom_extension_empty_properties():
    with pytest.raises(ValueError) as excinfo:
        @stix2.observables.CustomExtension(stix2.DomainName, 'x-new-ext2', {})
        class BarExtension():
            pass
    assert "'properties' must be a dict!" in str(excinfo.value)


def test_custom_extension_no_init():
    @stix2.observables.CustomExtension(stix2.DomainName, 'x-new-extension', {
        'property1': stix2.properties.StringProperty(required=True),
    })
    class NewExt():
        pass

    ne = NewExt(property1="foobar")
    assert ne.property1 == "foobar"

    @stix2.observables.CustomExtension(stix2.DomainName, 'x-new-ext2', {
        'property1': stix2.properties.StringProperty(required=True),
    })
    class NewExt2(object):
        pass

    ne2 = NewExt2(property1="foobar")
    assert ne2.property1 == "foobar"


def test_parse_observable_with_custom_extension():
    input_str = """{
        "type": "domain-name",
        "value": "example.com",
        "extensions": {
            "x-new-ext": {
                "property1": "foo",
                "property2": 12
            }
        }
    }"""

    parsed = stix2.parse_observable(input_str)
    assert parsed.extensions['x-new-ext'].property2 == 12


def test_parse_observable_with_unregistered_custom_extension():
    input_str = """{
        "type": "domain-name",
        "value": "example.com",
        "extensions": {
            "x-foobar-ext": {
                "property1": "foo",
                "property2": 12
            }
        }
    }"""

    with pytest.raises(ValueError) as excinfo:
        stix2.parse_observable(input_str)
    assert "Can't parse Unknown extension type" in str(excinfo.value)


def test_register_custom_object():
    # Not the way to register custom object.
    class CustomObject2(object):
        _type = 'awesome-object'

    stix2._register_type(CustomObject2)
    # Note that we will always check against newest OBJ_MAP.
    assert (CustomObject2._type, CustomObject2) in stix2.OBJ_MAP.items()
