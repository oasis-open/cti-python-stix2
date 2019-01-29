import pytest

import stix2

from .constants import FAKE_TIME, IDENTITY_ID, MARKING_DEFINITION_ID

IDENTITY_CUSTOM_PROP = stix2.v20.Identity(
    name="John Smith",
    identity_class="individual",
    x_foo="bar",
    allow_custom=True,
)


def test_identity_custom_property():
    with pytest.raises(ValueError) as excinfo:
        stix2.v20.Identity(
            id=IDENTITY_ID,
            created="2015-12-21T19:59:11Z",
            modified="2015-12-21T19:59:11Z",
            name="John Smith",
            identity_class="individual",
            custom_properties="foobar",
        )
    assert str(excinfo.value) == "'custom_properties' must be a dictionary"

    with pytest.raises(stix2.exceptions.ExtraPropertiesError) as excinfo:
        stix2.v20.Identity(
            id=IDENTITY_ID,
            created="2015-12-21T19:59:11Z",
            modified="2015-12-21T19:59:11Z",
            name="John Smith",
            identity_class="individual",
            custom_properties={
                "foo": "bar",
            },
            foo="bar",
        )
    assert "Unexpected properties for Identity" in str(excinfo.value)

    identity = stix2.v20.Identity(
        id=IDENTITY_ID,
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
        stix2.v20.Identity(
            id=IDENTITY_ID,
            created="2015-12-21T19:59:11Z",
            modified="2015-12-21T19:59:11Z",
            name="John Smith",
            identity_class="individual",
            x_foo="bar",
        )
    assert excinfo.value.cls == stix2.v20.Identity
    assert excinfo.value.properties == ['x_foo']
    assert "Unexpected properties for" in str(excinfo.value)


def test_identity_custom_property_allowed():
    identity = stix2.v20.Identity(
        id=IDENTITY_ID,
        created="2015-12-21T19:59:11Z",
        modified="2015-12-21T19:59:11Z",
        name="John Smith",
        identity_class="individual",
        x_foo="bar",
        allow_custom=True,
    )
    assert identity.x_foo == "bar"


@pytest.mark.parametrize(
    "data", [
        """{
        "type": "identity",
        "id": "identity--311b2d2d-f010-4473-83ec-1edf84858f4c",
        "created": "2015-12-21T19:59:11Z",
        "modified": "2015-12-21T19:59:11Z",
        "name": "John Smith",
        "identity_class": "individual",
        "foo": "bar"
    }""",
    ],
)
def test_parse_identity_custom_property(data):
    with pytest.raises(stix2.exceptions.ExtraPropertiesError) as excinfo:
        stix2.parse(data, version="2.0")
    assert excinfo.value.cls == stix2.v20.Identity
    assert excinfo.value.properties == ['foo']
    assert "Unexpected properties for" in str(excinfo.value)

    identity = stix2.parse(data, version="2.0", allow_custom=True)
    assert identity.foo == "bar"


def test_custom_property_object_in_bundled_object():
    bundle = stix2.v20.Bundle(IDENTITY_CUSTOM_PROP, allow_custom=True)

    assert bundle.objects[0].x_foo == "bar"
    assert '"x_foo": "bar"' in str(bundle)


def test_custom_properties_object_in_bundled_object():
    obj = stix2.v20.Identity(
        name="John Smith",
        identity_class="individual",
        custom_properties={
            "x_foo": "bar",
        },
    )
    bundle = stix2.v20.Bundle(obj, allow_custom=True)

    assert bundle.objects[0].x_foo == "bar"
    assert '"x_foo": "bar"' in str(bundle)


def test_custom_property_dict_in_bundled_object():
    custom_identity = {
        'type': 'identity',
        'id': IDENTITY_ID,
        'created': '2015-12-21T19:59:11Z',
        'name': 'John Smith',
        'identity_class': 'individual',
        'x_foo': 'bar',
    }
    with pytest.raises(stix2.exceptions.ExtraPropertiesError):
        stix2.v20.Bundle(custom_identity)

    bundle = stix2.v20.Bundle(custom_identity, allow_custom=True)
    assert bundle.objects[0].x_foo == "bar"
    assert '"x_foo": "bar"' in str(bundle)


def test_custom_properties_dict_in_bundled_object():
    custom_identity = {
        'type': 'identity',
        'id': IDENTITY_ID,
        'created': '2015-12-21T19:59:11Z',
        'name': 'John Smith',
        'identity_class': 'individual',
        'custom_properties': {
            'x_foo': 'bar',
        },
    }
    bundle = stix2.v20.Bundle(custom_identity)

    assert bundle.objects[0].x_foo == "bar"
    assert '"x_foo": "bar"' in str(bundle)


def test_custom_property_in_observed_data():
    artifact = stix2.v20.File(
        allow_custom=True,
        name='test',
        x_foo='bar',
    )
    observed_data = stix2.v20.ObservedData(
        allow_custom=True,
        first_observed="2015-12-21T19:00:00Z",
        last_observed="2015-12-21T19:00:00Z",
        number_observed=1,
        objects={"0": artifact},
    )

    assert observed_data.objects['0'].x_foo == "bar"
    assert '"x_foo": "bar"' in str(observed_data)


def test_custom_property_object_in_observable_extension():
    ntfs = stix2.v20.NTFSExt(
        allow_custom=True,
        sid=1,
        x_foo='bar',
    )
    artifact = stix2.v20.File(
        name='test',
        extensions={'ntfs-ext': ntfs},
    )
    observed_data = stix2.v20.ObservedData(
        allow_custom=True,
        first_observed="2015-12-21T19:00:00Z",
        last_observed="2015-12-21T19:00:00Z",
        number_observed=1,
        objects={"0": artifact},
    )

    assert observed_data.objects['0'].extensions['ntfs-ext'].x_foo == "bar"
    assert '"x_foo": "bar"' in str(observed_data)


def test_custom_property_dict_in_observable_extension():
    with pytest.raises(stix2.exceptions.ExtraPropertiesError):
        stix2.v20.File(
            name='test',
            extensions={
                'ntfs-ext': {
                    'sid': 1,
                    'x_foo': 'bar',
                },
            },
        )

    artifact = stix2.v20.File(
        allow_custom=True,
        name='test',
        extensions={
            'ntfs-ext': {
                'allow_custom': True,
                'sid': 1,
                'x_foo': 'bar',
            },
        },
    )
    observed_data = stix2.v20.ObservedData(
        allow_custom=True,
        first_observed="2015-12-21T19:00:00Z",
        last_observed="2015-12-21T19:00:00Z",
        number_observed=1,
        objects={"0": artifact},
    )

    assert observed_data.objects['0'].extensions['ntfs-ext'].x_foo == "bar"
    assert '"x_foo": "bar"' in str(observed_data)


def test_identity_custom_property_revoke():
    identity = IDENTITY_CUSTOM_PROP.revoke()
    assert identity.x_foo == "bar"


def test_identity_custom_property_edit_markings():
    marking_obj = stix2.v20.MarkingDefinition(
        id=MARKING_DEFINITION_ID,
        definition_type="statement",
        definition=stix2.v20.StatementMarking(statement="Copyright 2016, Example Corp"),
    )
    marking_obj2 = stix2.v20.MarkingDefinition(
        id=MARKING_DEFINITION_ID,
        definition_type="statement",
        definition=stix2.v20.StatementMarking(statement="Another one"),
    )

    # None of the following should throw exceptions
    identity = IDENTITY_CUSTOM_PROP.add_markings(marking_obj)
    identity2 = identity.add_markings(marking_obj2, ['x_foo'])
    identity2.remove_markings(marking_obj.id)
    identity2.remove_markings(marking_obj2.id, ['x_foo'])
    identity2.clear_markings()
    identity2.clear_markings('x_foo')


def test_custom_marking_no_init_1():
    @stix2.v20.CustomMarking(
        'x-new-obj', [
            ('property1', stix2.properties.StringProperty(required=True)),
        ],
    )
    class NewObj():
        pass

    no = NewObj(property1='something')
    assert no.property1 == 'something'


def test_custom_marking_no_init_2():
    @stix2.v20.CustomMarking(
        'x-new-obj2', [
            ('property1', stix2.properties.StringProperty(required=True)),
        ],
    )
    class NewObj2(object):
        pass

    no2 = NewObj2(property1='something')
    assert no2.property1 == 'something'


@stix2.v20.CustomObject(
    'x-new-type', [
        ('property1', stix2.properties.StringProperty(required=True)),
        ('property2', stix2.properties.IntegerProperty()),
    ],
)
class NewType(object):
    def __init__(self, property2=None, **kwargs):
        if property2 and property2 < 10:
            raise ValueError("'property2' is too small.")
        if "property3" in kwargs and not isinstance(kwargs.get("property3"), int):
            raise TypeError("Must be integer!")


def test_custom_object_raises_exception():
    with pytest.raises(TypeError) as excinfo:
        NewType(property1='something', property3='something', allow_custom=True)

    assert str(excinfo.value) == "Must be integer!"


def test_custom_object_type():
    nt = NewType(property1='something')
    assert nt.property1 == 'something'

    with pytest.raises(stix2.exceptions.MissingPropertiesError) as excinfo:
        NewType(property2=42)
    assert "No values for required properties" in str(excinfo.value)

    with pytest.raises(ValueError) as excinfo:
        NewType(property1='something', property2=4)
    assert "'property2' is too small." in str(excinfo.value)


def test_custom_object_no_init_1():
    @stix2.v20.CustomObject(
        'x-new-obj', [
            ('property1', stix2.properties.StringProperty(required=True)),
        ],
    )
    class NewObj():
        pass

    no = NewObj(property1='something')
    assert no.property1 == 'something'


def test_custom_object_no_init_2():
    @stix2.v20.CustomObject(
        'x-new-obj2', [
            ('property1', stix2.properties.StringProperty(required=True)),
        ],
    )
    class NewObj2(object):
        pass

    no2 = NewObj2(property1='something')
    assert no2.property1 == 'something'


def test_custom_object_invalid_type_name():
    with pytest.raises(ValueError) as excinfo:
        @stix2.v20.CustomObject(
            'x', [
                ('property1', stix2.properties.StringProperty(required=True)),
            ],
        )
        class NewObj(object):
            pass  # pragma: no cover
    assert "Invalid type name 'x': " in str(excinfo.value)

    with pytest.raises(ValueError) as excinfo:
        @stix2.v20.CustomObject(
            'x_new_object', [
                ('property1', stix2.properties.StringProperty(required=True)),
            ],
        )
        class NewObj2(object):
            pass  # pragma: no cover
    assert "Invalid type name 'x_new_object':" in str(excinfo.value)


def test_parse_custom_object_type():
    nt_string = """{
        "type": "x-new-type",
        "created": "2015-12-21T19:59:11Z",
        "property1": "something"
    }"""

    nt = stix2.parse(nt_string, version="2.0", allow_custom=True)
    assert nt["property1"] == 'something'


def test_parse_unregistered_custom_object_type():
    nt_string = """{
        "type": "x-foobar-observable",
        "created": "2015-12-21T19:59:11Z",
        "property1": "something"
    }"""

    with pytest.raises(stix2.exceptions.ParseError) as excinfo:
        stix2.parse(nt_string, version="2.0")
    assert "Can't parse unknown object type" in str(excinfo.value)
    assert "use the CustomObject decorator." in str(excinfo.value)


def test_parse_unregistered_custom_object_type_w_allow_custom():
    """parse an unknown custom object, allowed by passing
    'allow_custom' flag
    """
    nt_string = """{
        "type": "x-foobar-observable",
        "created": "2015-12-21T19:59:11Z",
        "property1": "something"
    }"""

    custom_obj = stix2.parse(nt_string, version="2.0", allow_custom=True)
    assert custom_obj["type"] == "x-foobar-observable"


@stix2.v20.CustomObservable(
    'x-new-observable', [
        ('property1', stix2.properties.StringProperty(required=True)),
        ('property2', stix2.properties.IntegerProperty()),
        ('x_property3', stix2.properties.BooleanProperty()),
    ],
)
class NewObservable():
    def __init__(self, property2=None, **kwargs):
        if property2 and property2 < 10:
            raise ValueError("'property2' is too small.")
        if "property3" in kwargs and not isinstance(kwargs.get("property3"), int):
            raise TypeError("Must be integer!")


def test_custom_observable_object_1():
    no = NewObservable(property1='something')
    assert no.property1 == 'something'


def test_custom_observable_object_2():
    with pytest.raises(stix2.exceptions.MissingPropertiesError) as excinfo:
        NewObservable(property2=42)
    assert excinfo.value.properties == ['property1']
    assert "No values for required properties" in str(excinfo.value)


def test_custom_observable_object_3():
    with pytest.raises(ValueError) as excinfo:
        NewObservable(property1='something', property2=4)
    assert "'property2' is too small." in str(excinfo.value)


def test_custom_observable_raises_exception():
    with pytest.raises(TypeError) as excinfo:
        NewObservable(property1='something', property3='something', allow_custom=True)

    assert str(excinfo.value) == "Must be integer!"


def test_custom_observable_object_no_init_1():
    @stix2.v20.CustomObservable(
        'x-new-observable', [
            ('property1', stix2.properties.StringProperty()),
        ],
    )
    class NewObs():
        pass

    no = NewObs(property1='something')
    assert no.property1 == 'something'


def test_custom_observable_object_no_init_2():
    @stix2.v20.CustomObservable(
        'x-new-obs2', [
            ('property1', stix2.properties.StringProperty()),
        ],
    )
    class NewObs2(object):
        pass

    no2 = NewObs2(property1='something')
    assert no2.property1 == 'something'


def test_custom_observable_object_invalid_type_name():
    with pytest.raises(ValueError) as excinfo:
        @stix2.v20.CustomObservable(
            'x', [
                ('property1', stix2.properties.StringProperty()),
            ],
        )
        class NewObs(object):
            pass  # pragma: no cover
    assert "Invalid observable type name 'x':" in str(excinfo.value)

    with pytest.raises(ValueError) as excinfo:
        @stix2.v20.CustomObservable(
            'x_new_obs', [
                ('property1', stix2.properties.StringProperty()),
            ],
        )
        class NewObs2(object):
            pass  # pragma: no cover
    assert "Invalid observable type name 'x_new_obs':" in str(excinfo.value)


def test_custom_observable_object_invalid_ref_property():
    with pytest.raises(ValueError) as excinfo:
        @stix2.v20.CustomObservable(
            'x-new-obs', [
                ('property_ref', stix2.properties.StringProperty()),
            ],
        )
        class NewObs():
            pass
    assert "is named like an object reference property but is not an ObjectReferenceProperty" in str(excinfo.value)


def test_custom_observable_object_invalid_refs_property():
    with pytest.raises(ValueError) as excinfo:
        @stix2.v20.CustomObservable(
            'x-new-obs', [
                ('property_refs', stix2.properties.StringProperty()),
            ],
        )
        class NewObs():
            pass
    assert "is named like an object reference list property but is not a ListProperty containing ObjectReferenceProperty" in str(excinfo.value)


def test_custom_observable_object_invalid_refs_list_property():
    with pytest.raises(ValueError) as excinfo:
        @stix2.v20.CustomObservable(
            'x-new-obs', [
                ('property_refs', stix2.properties.ListProperty(stix2.properties.StringProperty)),
            ],
        )
        class NewObs():
            pass
    assert "is named like an object reference list property but is not a ListProperty containing ObjectReferenceProperty" in str(excinfo.value)


def test_custom_observable_object_invalid_valid_refs():
    @stix2.v20.CustomObservable(
        'x-new-obs', [
            ('property1', stix2.properties.StringProperty(required=True)),
            ('property_ref', stix2.properties.ObjectReferenceProperty(valid_types='email-addr')),
        ],
    )
    class NewObs():
        pass

    with pytest.raises(Exception) as excinfo:
        NewObs(
            _valid_refs=['1'],
            property1='something',
            property_ref='1',
        )
    assert "must be created with _valid_refs as a dict, not a list" in str(excinfo.value)


def test_custom_no_properties_raises_exception():
    with pytest.raises(TypeError):

        @stix2.v20.CustomObject('x-new-object-type')
        class NewObject1(object):
            pass


def test_custom_wrong_properties_arg_raises_exception():
    with pytest.raises(ValueError):

        @stix2.v20.CustomObservable('x-new-object-type', (("prop", stix2.properties.BooleanProperty())))
        class NewObject2(object):
            pass


def test_parse_custom_observable_object():
    nt_string = """{
        "type": "x-new-observable",
        "property1": "something"
    }"""

    nt = stix2.parse_observable(nt_string, [], version='2.0')
    assert isinstance(nt, stix2.base._STIXBase)
    assert nt.property1 == 'something'


def test_parse_unregistered_custom_observable_object():
    nt_string = """{
        "type": "x-foobar-observable",
        "property1": "something"
    }"""

    with pytest.raises(stix2.exceptions.CustomContentError) as excinfo:
        stix2.parse_observable(nt_string, version='2.0')
    assert "Can't parse unknown observable type" in str(excinfo.value)

    parsed_custom = stix2.parse_observable(nt_string, allow_custom=True, version='2.0')
    assert parsed_custom['property1'] == 'something'
    with pytest.raises(AttributeError) as excinfo:
        assert parsed_custom.property1 == 'something'
    assert not isinstance(parsed_custom, stix2.base._STIXBase)


def test_parse_unregistered_custom_observable_object_with_no_type():
    nt_string = """{
        "property1": "something"
    }"""

    with pytest.raises(stix2.exceptions.ParseError) as excinfo:
        stix2.parse_observable(nt_string, allow_custom=True, version='2.0')
    assert "Can't parse observable with no 'type' property" in str(excinfo.value)


def test_parse_observed_data_with_custom_observable():
    input_str = """{
        "type": "observed-data",
        "id": "observed-data--dc20c4ca-a2a3-4090-a5d5-9558c3af4758",
        "created": "2016-04-06T19:58:16.000Z",
        "modified": "2016-04-06T19:58:16.000Z",
        "first_observed": "2015-12-21T19:00:00Z",
        "last_observed": "2015-12-21T19:00:00Z",
        "number_observed": 1,
        "objects": {
            "0": {
                "type": "x-foobar-observable",
                "property1": "something"
            }
        }
    }"""
    parsed = stix2.parse(input_str, version="2.0", allow_custom=True)
    assert parsed.objects['0']['property1'] == 'something'


def test_parse_invalid_custom_observable_object():
    nt_string = """{
        "property1": "something"
    }"""

    with pytest.raises(stix2.exceptions.ParseError) as excinfo:
        stix2.parse_observable(nt_string, version='2.0')
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
    ob_data = stix2.v20.ObservedData(
        first_observed=FAKE_TIME,
        last_observed=FAKE_TIME,
        number_observed=1,
        objects={'0': no},
        allow_custom=True,
    )
    assert ob_data.objects['0'].property1 == 'something'


@stix2.v20.CustomExtension(
    stix2.v20.DomainName, 'x-new-ext', [
        ('property1', stix2.properties.StringProperty(required=True)),
        ('property2', stix2.properties.IntegerProperty()),
    ],
)
class NewExtension():
    def __init__(self, property2=None, **kwargs):
        if property2 and property2 < 10:
            raise ValueError("'property2' is too small.")
        if "property3" in kwargs and not isinstance(kwargs.get("property3"), int):
            raise TypeError("Must be integer!")


def test_custom_extension_raises_exception():
    with pytest.raises(TypeError) as excinfo:
        NewExtension(property1='something', property3='something', allow_custom=True)

    assert str(excinfo.value) == "Must be integer!"


def test_custom_extension():
    ext = NewExtension(property1='something')
    assert ext.property1 == 'something'

    with pytest.raises(stix2.exceptions.MissingPropertiesError) as excinfo:
        NewExtension(property2=42)
    assert excinfo.value.properties == ['property1']
    assert str(excinfo.value) == "No values for required properties for _CustomExtension: (property1)."

    with pytest.raises(ValueError) as excinfo:
        NewExtension(property1='something', property2=4)
    assert str(excinfo.value) == "'property2' is too small."


def test_custom_extension_wrong_observable_type():
    # NewExtension is an extension of DomainName, not File
    ext = NewExtension(property1='something')
    with pytest.raises(ValueError) as excinfo:
        stix2.v20.File(
            name="abc.txt",
            extensions={
                "ntfs-ext": ext,
            },
        )

    assert 'Cannot determine extension type' in excinfo.value.reason


@pytest.mark.parametrize(
    "data", [
        """{
    "keys": [
        {
            "test123": 123,
            "test345": "aaaa"
        }
    ]
}""",
    ],
)
def test_custom_extension_with_list_and_dict_properties_observable_type(data):
    @stix2.v20.CustomExtension(
        stix2.v20.UserAccount, 'some-extension', [
            ('keys', stix2.properties.ListProperty(stix2.properties.DictionaryProperty, required=True)),
        ],
    )
    class SomeCustomExtension:
        pass

    example = SomeCustomExtension(keys=[{'test123': 123, 'test345': 'aaaa'}])
    assert data == str(example)


def test_custom_extension_invalid_observable():
    # These extensions are being applied to improperly-created Observables.
    # The Observable classes should have been created with the CustomObservable decorator.
    class Foo(object):
        pass
    with pytest.raises(ValueError) as excinfo:
        @stix2.v20.CustomExtension(
            Foo, 'x-new-ext', [
                ('property1', stix2.properties.StringProperty(required=True)),
            ],
        )
        class FooExtension():
            pass  # pragma: no cover
    assert str(excinfo.value) == "'observable' must be a valid Observable class!"

    class Bar(stix2.v20.observables._Observable):
        pass
    with pytest.raises(ValueError) as excinfo:
        @stix2.v20.CustomExtension(
            Bar, 'x-new-ext', [
                ('property1', stix2.properties.StringProperty(required=True)),
            ],
        )
        class BarExtension():
            pass
    assert "Unknown observable type" in str(excinfo.value)
    assert "Custom observables must be created with the @CustomObservable decorator." in str(excinfo.value)

    class Baz(stix2.v20.observables._Observable):
        _type = 'Baz'
    with pytest.raises(ValueError) as excinfo:
        @stix2.v20.CustomExtension(
            Baz, 'x-new-ext', [
                ('property1', stix2.properties.StringProperty(required=True)),
            ],
        )
        class BazExtension():
            pass
    assert "Unknown observable type" in str(excinfo.value)
    assert "Custom observables must be created with the @CustomObservable decorator." in str(excinfo.value)


def test_custom_extension_invalid_type_name():
    with pytest.raises(ValueError) as excinfo:
        @stix2.v20.CustomExtension(
            stix2.v20.File, 'x', {
                'property1': stix2.properties.StringProperty(required=True),
            },
        )
        class FooExtension():
            pass  # pragma: no cover
    assert "Invalid extension type name 'x':" in str(excinfo.value)

    with pytest.raises(ValueError) as excinfo:
        @stix2.v20.CustomExtension(
            stix2.File, 'x_new_ext', {
                'property1': stix2.properties.StringProperty(required=True),
            },
        )
        class BlaExtension():
            pass  # pragma: no cover
    assert "Invalid extension type name 'x_new_ext':" in str(excinfo.value)


def test_custom_extension_no_properties():
    with pytest.raises(ValueError) as excinfo:
        @stix2.v20.CustomExtension(stix2.v20.DomainName, 'x-new-ext2', None)
        class BarExtension():
            pass
    assert "Must supply a list, containing tuples." in str(excinfo.value)


def test_custom_extension_empty_properties():
    with pytest.raises(ValueError) as excinfo:
        @stix2.v20.CustomExtension(stix2.v20.DomainName, 'x-new-ext2', [])
        class BarExtension():
            pass
    assert "Must supply a list, containing tuples." in str(excinfo.value)


def test_custom_extension_dict_properties():
    with pytest.raises(ValueError) as excinfo:
        @stix2.v20.CustomExtension(stix2.v20.DomainName, 'x-new-ext2', {})
        class BarExtension():
            pass
    assert "Must supply a list, containing tuples." in str(excinfo.value)


def test_custom_extension_no_init_1():
    @stix2.v20.CustomExtension(
        stix2.v20.DomainName, 'x-new-extension', [
            ('property1', stix2.properties.StringProperty(required=True)),
        ],
    )
    class NewExt():
        pass

    ne = NewExt(property1="foobar")
    assert ne.property1 == "foobar"


def test_custom_extension_no_init_2():
    @stix2.v20.CustomExtension(
        stix2.v20.DomainName, 'x-new-ext2', [
            ('property1', stix2.properties.StringProperty(required=True)),
        ],
    )
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

    parsed = stix2.parse_observable(input_str, version='2.0')
    assert parsed.extensions['x-new-ext'].property2 == 12


@pytest.mark.parametrize(
    "data", [
        # URL is not in EXT_MAP
        """{
        "type": "url",
        "value": "example.com",
        "extensions": {
            "x-foobar-ext": {
                "property1": "foo",
                "property2": 12
            }
        }
    }""",
        # File is in EXT_MAP
        """{
        "type": "file",
        "name": "foo.txt",
        "extensions": {
            "x-foobar-ext": {
                "property1": "foo",
                "property2": 12
            }
        }
    }""",
    ],
)
def test_parse_observable_with_unregistered_custom_extension(data):
    with pytest.raises(ValueError) as excinfo:
        stix2.parse_observable(data, version='2.0')
    assert "Can't parse unknown extension type" in str(excinfo.value)

    parsed_ob = stix2.parse_observable(data, allow_custom=True, version='2.0')
    assert parsed_ob['extensions']['x-foobar-ext']['property1'] == 'foo'
    assert not isinstance(parsed_ob['extensions']['x-foobar-ext'], stix2.base._STIXBase)


def test_register_custom_object():
    # Not the way to register custom object.
    class CustomObject2(object):
        _type = 'awesome-object'

    stix2.core._register_object(CustomObject2, version="2.0")
    # Note that we will always check against newest OBJ_MAP.
    assert (CustomObject2._type, CustomObject2) in stix2.v20.OBJ_MAP.items()


def test_extension_property_location():
    assert 'extensions' in stix2.v20.OBJ_MAP_OBSERVABLE['x-new-observable']._properties
    assert 'extensions' not in stix2.v20.EXT_MAP['domain-name']['x-new-ext']._properties


@pytest.mark.parametrize(
    "data", [
        """{
    "type": "x-example",
    "id": "x-example--336d8a9f-91f1-46c5-b142-6441bb9f8b8d",
    "created": "2018-06-12T16:20:58.059Z",
    "modified": "2018-06-12T16:20:58.059Z",
    "dictionary": {
        "key": {
            "key_a": "value",
            "key_b": "value"
        }
    }
}""",
    ],
)
def test_custom_object_nested_dictionary(data):
    @stix2.v20.CustomObject(
        'x-example', [
            ('dictionary', stix2.properties.DictionaryProperty()),
        ],
    )
    class Example(object):
        def __init__(self, **kwargs):
            pass

    example = Example(
        id='x-example--336d8a9f-91f1-46c5-b142-6441bb9f8b8d',
        created='2018-06-12T16:20:58.059Z',
        modified='2018-06-12T16:20:58.059Z',
        dictionary={'key': {'key_b': 'value', 'key_a': 'value'}},
    )

    assert data == str(example)
