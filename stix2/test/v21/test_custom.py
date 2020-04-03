import uuid

import pytest

import stix2
import stix2.base
import stix2.v21

from ...exceptions import DuplicateRegistrationError, InvalidValueError
from .constants import FAKE_TIME, IDENTITY_ID, MARKING_DEFINITION_ID

# Custom Properties in SDOs

IDENTITY_CUSTOM_PROP = stix2.v21.Identity(
    name="John Smith",
    identity_class="individual",
    x_foo="bar",
    allow_custom=True,
)


def test_identity_custom_property():
    identity = stix2.v21.Identity(
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

    with pytest.raises(ValueError) as excinfo:
        stix2.v21.Identity(
            id=IDENTITY_ID,
            created="2015-12-21T19:59:11Z",
            modified="2015-12-21T19:59:11Z",
            name="John Smith",
            identity_class="individual",
            custom_properties="foobar",
        )
    assert str(excinfo.value) == "'custom_properties' must be a dictionary"

    with pytest.raises(stix2.exceptions.ExtraPropertiesError) as excinfo:
        stix2.v21.Identity(
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

    # leading numeric character is illegal in 2.1

    with pytest.raises(stix2.exceptions.InvalidValueError) as excinfo:
        stix2.v21.Identity(
            id=IDENTITY_ID,
            created="2015-12-21T19:59:11Z",
            modified="2015-12-21T19:59:11Z",
            name="John Smith",
            identity_class="individual",
            custom_properties={
                "7foo": "bar",
            },
        )
    assert "must begin with an alpha character." in str(excinfo.value)

    # leading "_" is illegal in 2.1

    with pytest.raises(stix2.exceptions.InvalidValueError) as excinfo:
        stix2.v21.Identity(
            id=IDENTITY_ID,
            created="2015-12-21T19:59:11Z",
            modified="2015-12-21T19:59:11Z",
            name="John Smith",
            identity_class="individual",
            custom_properties={
                "_foo": "bar",
            },
        )
    assert "must begin with an alpha character." in str(excinfo.value)

    with pytest.raises(stix2.exceptions.InvalidValueError) as excinfo:
        identity = stix2.v21.Identity(
            id=IDENTITY_ID,
            created="2015-12-21T19:59:11Z",
            modified="2015-12-21T19:59:11Z",
            name="John Smith",
            identity_class="individual",
            _x_foo="bar",
            allow_custom=True,
        )
    assert "must begin with an alpha character." in str(excinfo.value)


def test_identity_custom_property_invalid():
    with pytest.raises(stix2.exceptions.ExtraPropertiesError) as excinfo:
        stix2.v21.Identity(
            id=IDENTITY_ID,
            created="2015-12-21T19:59:11Z",
            modified="2015-12-21T19:59:11Z",
            name="John Smith",
            identity_class="individual",
            x_foo="bar",
        )
    assert excinfo.value.cls == stix2.v21.Identity
    assert excinfo.value.properties == ['x_foo']
    assert "Unexpected properties for" in str(excinfo.value)


def test_identity_custom_property_allowed():
    identity = stix2.v21.Identity(
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
        "spec_version": "2.1",
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
        stix2.parse(data, version="2.1")
    assert issubclass(excinfo.value.cls, stix2.v21.Identity)
    assert excinfo.value.properties == ['foo']
    assert "Unexpected properties for" in str(excinfo.value)

    identity = stix2.parse(data, version="2.1", allow_custom=True)
    assert identity.foo == "bar"


def test_custom_property_object_in_bundled_object():
    bundle = stix2.v21.Bundle(IDENTITY_CUSTOM_PROP, allow_custom=True)

    assert bundle.objects[0].x_foo == "bar"
    assert '"x_foo": "bar"' in str(bundle)


def test_custom_properties_object_in_bundled_object():
    obj = stix2.v21.Identity(
        name="John Smith",
        identity_class="individual",
        custom_properties={
            "x_foo": "bar",
        },
    )
    bundle = stix2.v21.Bundle(obj, allow_custom=True)

    assert bundle.objects[0].x_foo == "bar"
    assert '"x_foo": "bar"' in str(bundle)


def test_custom_property_dict_in_bundled_object():
    custom_identity = {
        'type': 'identity',
        'spec_version': '2.1',
        'id': IDENTITY_ID,
        'created': '2015-12-21T19:59:11Z',
        'name': 'John Smith',
        'identity_class': 'individual',
        'x_foo': 'bar',
    }
    with pytest.raises(InvalidValueError):
        stix2.v21.Bundle(custom_identity)

    bundle = stix2.v21.Bundle(custom_identity, allow_custom=True)
    assert bundle.objects[0].x_foo == "bar"
    assert '"x_foo": "bar"' in str(bundle)


def test_custom_properties_dict_in_bundled_object():
    custom_identity = {
        'type': 'identity',
        'spec_version': '2.1',
        'id': IDENTITY_ID,
        'created': '2015-12-21T19:59:11Z',
        'name': 'John Smith',
        'identity_class': 'individual',
        'custom_properties': {
            'x_foo': 'bar',
        },
    }
    bundle = stix2.v21.Bundle(custom_identity)

    assert bundle.objects[0].x_foo == "bar"
    assert '"x_foo": "bar"' in str(bundle)

# Custom properties in SCOs


def test_custom_property_in_observed_data():
    artifact = stix2.v21.File(
        allow_custom=True,
        name='test',
        x_foo='bar',
    )
    observed_data = stix2.v21.ObservedData(
        allow_custom=True,
        first_observed="2015-12-21T19:00:00Z",
        last_observed="2015-12-21T19:00:00Z",
        number_observed=1,
        objects={"0": artifact},
    )

    assert observed_data.objects['0'].x_foo == "bar"
    assert '"x_foo": "bar"' in str(observed_data)


def test_invalid_custom_property_in_observed_data():
    with pytest.raises(stix2.exceptions.InvalidValueError) as excinfo:
        stix2.v21.File(
            custom_properties={"8foo": 1},
            allow_custom=True,
            name='test',
            x_foo='bar',
        )

    assert "must begin with an alpha character." in str(excinfo.value)


def test_custom_property_object_in_observable_extension():
    ntfs = stix2.v21.NTFSExt(
        allow_custom=True,
        sid=1,
        x_foo='bar',
    )
    artifact = stix2.v21.File(
        name='test',
        extensions={'ntfs-ext': ntfs},
    )
    observed_data = stix2.v21.ObservedData(
        allow_custom=True,
        first_observed="2015-12-21T19:00:00Z",
        last_observed="2015-12-21T19:00:00Z",
        number_observed=1,
        objects={"0": artifact},
    )

    assert observed_data.objects['0'].extensions['ntfs-ext'].x_foo == "bar"
    assert '"x_foo": "bar"' in str(observed_data)


def test_custom_property_dict_in_observable_extension():
    with pytest.raises(InvalidValueError):
        stix2.v21.File(
            name='test',
            extensions={
                'ntfs-ext': {
                    'sid': 1,
                    'x_foo': 'bar',
                },
            },
        )

    artifact = stix2.v21.File(
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
    observed_data = stix2.v21.ObservedData(
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

# Custom markings


def test_identity_custom_property_edit_markings():
    marking_obj = stix2.v21.MarkingDefinition(
        id=MARKING_DEFINITION_ID,
        definition_type="statement",
        definition=stix2.v21.StatementMarking(statement="Copyright 2016, Example Corp"),
    )
    marking_obj2 = stix2.v21.MarkingDefinition(
        id=MARKING_DEFINITION_ID,
        definition_type="statement",
        definition=stix2.v21.StatementMarking(statement="Another one"),
    )

    # None of the following should throw exceptions
    identity = IDENTITY_CUSTOM_PROP.add_markings(marking_obj)
    identity2 = identity.add_markings(marking_obj2, ['x_foo'])
    identity2.remove_markings(marking_obj.id)
    identity2.remove_markings(marking_obj2.id, ['x_foo'])
    identity2.clear_markings()
    identity2.clear_markings('x_foo')


def test_invalid_custom_property_in_marking():
    with pytest.raises(ValueError) as excinfo:
        @stix2.v21.CustomMarking(
            'x-new-obj', [
                ('9property1', stix2.properties.StringProperty(required=True)),
            ],
        )
        class NewObj():
            pass

    assert "must begin with an alpha character." in str(excinfo.value)


def test_custom_marking_no_init_1():
    @stix2.v21.CustomMarking(
        'x-new-obj', [
            ('property1', stix2.properties.StringProperty(required=True)),
        ],
    )
    class NewObj():
        pass

    no = NewObj(property1='something')
    assert no.property1 == 'something'


def test_custom_marking_no_init_2():
    @stix2.v21.CustomMarking(
        'x-new-obj2', [
            ('property1', stix2.properties.StringProperty(required=True)),
        ],
    )
    class NewObj2(object):
        pass

    no2 = NewObj2(property1='something')
    assert no2.property1 == 'something'


def test_custom_marking_invalid_type_name():
    with pytest.raises(ValueError) as excinfo:
        @stix2.v21.CustomMarking(
            'x', [
                ('property1', stix2.properties.StringProperty(required=True)),
            ],
        )
        class NewObj(object):
            pass  # pragma: no cover
    assert "Invalid type name 'x': " in str(excinfo.value)

    with pytest.raises(ValueError) as excinfo:
        @stix2.v21.CustomMarking(
            'x_new_marking', [
                ('property1', stix2.properties.StringProperty(required=True)),
            ],
        )
        class NewObj2(object):
            pass  # pragma: no cover
    assert "Invalid type name 'x_new_marking':" in str(excinfo.value)

    with pytest.raises(ValueError) as excinfo:
        @stix2.v21.CustomMarking(
            '7x-new-marking', [
                ('property1', stix2.properties.StringProperty(required=True)),
            ],
        )
        class NewObj3(object):
            pass  # pragma: no cover
    assert "Invalid type name '7x-new-marking':" in str(excinfo.value)

# Custom Objects


@stix2.v21.CustomObject(
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
    @stix2.v21.CustomObject(
        'x-new-obj', [
            ('property1', stix2.properties.StringProperty(required=True)),
        ],
    )
    class NewObj():
        pass

    no = NewObj(property1='something')
    assert no.property1 == 'something'


def test_custom_object_no_init_2():
    @stix2.v21.CustomObject(
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
        @stix2.v21.CustomObject(
            'x', [
                ('property1', stix2.properties.StringProperty(required=True)),
            ],
        )
        class NewObj(object):
            pass  # pragma: no cover
    assert "Invalid type name 'x': " in str(excinfo.value)

    with pytest.raises(ValueError) as excinfo:
        @stix2.v21.CustomObject(
            'x_new_object', [
                ('property1', stix2.properties.StringProperty(required=True)),
            ],
        )
        class NewObj2(object):
            pass  # pragma: no cover
    assert "Invalid type name 'x_new_object':" in str(excinfo.value)

    with pytest.raises(ValueError) as excinfo:
        @stix2.v21.CustomObject(
            '7x-new-object', [
                ('property1', stix2.properties.StringProperty(required=True)),
            ],
        )
        class NewObj3(object):
            pass  # pragma: no cover
    assert "Invalid type name '7x-new-object':" in str(excinfo.value)


def test_parse_custom_object_type():
    nt_string = """{
        "type": "x-new-type",
        "created": "2015-12-21T19:59:11Z",
        "property1": "something"
    }"""

    nt = stix2.parse(nt_string, allow_custom=True)
    assert nt["property1"] == 'something'


def test_parse_unregistered_custom_object_type():
    nt_string = """{
        "type": "x-foobar-observable",
        "created": "2015-12-21T19:59:11Z",
        "property1": "something"
    }"""

    with pytest.raises(stix2.exceptions.ParseError) as excinfo:
        stix2.parse(nt_string, version="2.1")
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

    custom_obj = stix2.parse(nt_string, version="2.1", allow_custom=True)
    assert custom_obj["type"] == "x-foobar-observable"

# Custom SCOs


@stix2.v21.CustomObservable(
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
    @stix2.v21.CustomObservable(
        'x-new-observable-2', [
            ('property1', stix2.properties.StringProperty()),
        ],
    )
    class NewObs():
        pass

    no = NewObs(property1='something')
    assert no.property1 == 'something'


def test_custom_observable_object_no_init_2():
    @stix2.v21.CustomObservable(
        'x-new-obs2', [
            ('property1', stix2.properties.StringProperty()),
        ],
    )
    class NewObs2(object):
        pass

    no2 = NewObs2(property1='something')
    assert no2.property1 == 'something'


def test_invalid_custom_property_in_custom_observable_object():
    with pytest.raises(ValueError) as excinfo:
        @stix2.v21.CustomObservable(
            'x-new-sco', [
                ('5property1', stix2.properties.StringProperty()),
            ],
        )
        class NewObs(object):
            pass  # pragma: no cover
    assert "must begin with an alpha character." in str(excinfo.value)


def test_custom_observable_object_invalid_type_name():
    with pytest.raises(ValueError) as excinfo:
        @stix2.v21.CustomObservable(
            'x', [
                ('property1', stix2.properties.StringProperty()),
            ],
        )
        class NewObs(object):
            pass  # pragma: no cover
    assert "Invalid type name 'x':" in str(excinfo.value)

    with pytest.raises(ValueError) as excinfo:
        @stix2.v21.CustomObservable(
            'x_new_obs', [
                ('property1', stix2.properties.StringProperty()),
            ],
        )
        class NewObs2(object):
            pass  # pragma: no cover
    assert "Invalid type name 'x_new_obs':" in str(excinfo.value)

    with pytest.raises(ValueError) as excinfo:
        @stix2.v21.CustomObservable(
            '7x-new-obs', [
                ('property1', stix2.properties.StringProperty()),
            ],
        )
        class NewObs3(object):
            pass  # pragma: no cover
    assert "Invalid type name '7x-new-obs':" in str(excinfo.value)


def test_custom_observable_object_invalid_ref_property():
    with pytest.raises(ValueError) as excinfo:
        @stix2.v21.CustomObservable(
            'x-new-obs', [
                ('property_ref', stix2.properties.StringProperty()),
            ],
        )
        class NewObs():
            pass
    assert "is named like a reference property but is not a ReferenceProperty" in str(excinfo.value)


def test_custom_observable_object_invalid_refs_property():
    with pytest.raises(ValueError) as excinfo:
        @stix2.v21.CustomObservable(
            'x-new-obs', [
                ('property_refs', stix2.properties.StringProperty()),
            ],
        )
        class NewObs():
            pass
    assert "is named like a reference list property but is not a ListProperty containing ReferenceProperty" in str(excinfo.value)


def test_custom_observable_object_invalid_refs_list_property():
    with pytest.raises(ValueError) as excinfo:
        @stix2.v21.CustomObservable(
            'x-new-obs', [
                ('property_refs', stix2.properties.ListProperty(stix2.properties.StringProperty)),
            ],
        )
        class NewObs():
            pass
    assert "is named like a reference list property but is not a ListProperty containing ReferenceProperty" in str(excinfo.value)


def test_custom_no_properties_raises_exception():
    with pytest.raises(TypeError):

        @stix2.v21.CustomObject('x-new-object-type')
        class NewObject1(object):
            pass


def test_custom_wrong_properties_arg_raises_exception():
    with pytest.raises(ValueError):

        @stix2.v21.CustomObservable('x-new-object-type', (("prop", stix2.properties.BooleanProperty())))
        class NewObject2(object):
            pass


def test_parse_custom_observable_object():
    nt_string = """{
        "type": "x-new-observable",
        "property1": "something"
    }"""
    nt = stix2.parse(nt_string, [], version='2.1')
    assert isinstance(nt, stix2.base._STIXBase)
    assert nt.property1 == 'something'


def test_parse_unregistered_custom_observable_object():
    nt_string = """{
        "type": "x-foobar-observable",
        "property1": "something"
    }"""

    with pytest.raises(stix2.exceptions.ParseError) as excinfo:
        stix2.parse(nt_string, version='2.1')
    assert "Can't parse unknown object type" in str(excinfo.value)
    parsed_custom = stix2.parse(nt_string, allow_custom=True, version='2.1')
    assert parsed_custom['property1'] == 'something'
    with pytest.raises(AttributeError) as excinfo:
        assert parsed_custom.property1 == 'something'
    assert not isinstance(parsed_custom, stix2.base._STIXBase)


def test_parse_unregistered_custom_observable_object_with_no_type():
    nt_string = """{
        "property1": "something"
    }"""

    with pytest.raises(stix2.exceptions.ParseError) as excinfo:
        stix2.parse(nt_string, allow_custom=True, version='2.1')
    assert "Can't parse object with no 'type' property" in str(excinfo.value)


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
    parsed = stix2.parse(input_str, version="2.1", allow_custom=True)
    assert parsed.objects['0']['property1'] == 'something'


def test_parse_invalid_custom_observable_object():
    nt_string = """{
        "property1": "something"
    }"""

    with pytest.raises(stix2.exceptions.ParseError) as excinfo:
        stix2.parse(nt_string, version='2.1')
    assert "Can't parse object with no 'type' property" in str(excinfo.value)


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
    ob_data = stix2.v21.ObservedData(
        first_observed=FAKE_TIME,
        last_observed=FAKE_TIME,
        number_observed=1,
        objects={'0': no},
        allow_custom=True,
    )
    assert ob_data.objects['0'].property1 == 'something'


def test_custom_observable_object_det_id_1():
    @stix2.v21.CustomObservable(
        'x-det-id-observable-1', [
            ('property1', stix2.properties.StringProperty(required=True)),
            ('property2', stix2.properties.IntegerProperty()),
        ], [
            'property1',
        ],
    )
    class DetIdObs1():
        pass

    dio_1 = DetIdObs1(property1='I am property1!', property2=42)
    dio_2 = DetIdObs1(property1='I am property1!', property2=24)
    assert dio_1.property1 == dio_2.property1 == 'I am property1!'
    assert dio_1.id == dio_2.id

    uuid_obj = uuid.UUID(dio_1.id[-36:])
    assert uuid_obj.variant == uuid.RFC_4122
    assert uuid_obj.version == 5

    dio_3 = DetIdObs1(property1='I am property1!', property2=42)
    dio_4 = DetIdObs1(property1='I am also property1!', property2=24)
    assert dio_3.property1 == 'I am property1!'
    assert dio_4.property1 == 'I am also property1!'
    assert dio_3.id != dio_4.id


def test_custom_observable_object_det_id_2():
    @stix2.v21.CustomObservable(
        'x-det-id-observable-2', [
            ('property1', stix2.properties.StringProperty(required=True)),
            ('property2', stix2.properties.IntegerProperty()),
        ], [
            'property1', 'property2',
        ],
    )
    class DetIdObs2():
        pass

    dio_1 = DetIdObs2(property1='I am property1!', property2=42)
    dio_2 = DetIdObs2(property1='I am property1!', property2=42)
    assert dio_1.property1 == dio_2.property1 == 'I am property1!'
    assert dio_1.property2 == dio_2.property2 == 42
    assert dio_1.id == dio_2.id

    dio_3 = DetIdObs2(property1='I am property1!', property2=42)
    dio_4 = DetIdObs2(property1='I am also property1!', property2=42)
    assert dio_3.property1 == 'I am property1!'
    assert dio_4.property1 == 'I am also property1!'
    assert dio_3.property2 == dio_4.property2 == 42
    assert dio_3.id != dio_4.id


def test_custom_observable_object_no_id_contrib_props():
    @stix2.v21.CustomObservable(
        'x-det-id-observable-3', [
            ('property1', stix2.properties.StringProperty(required=True)),
        ],
    )
    class DetIdObs3():
        pass

    dio = DetIdObs3(property1="I am property1!")

    uuid_obj = uuid.UUID(dio.id[-36:])
    assert uuid_obj.variant == uuid.RFC_4122
    assert uuid_obj.version == 4

# Custom Extensions


@stix2.v21.CustomExtension(
    stix2.v21.DomainName, 'x-new-ext', [
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
    with pytest.raises(InvalidValueError) as excinfo:
        stix2.v21.File(
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
    @stix2.v21.CustomExtension(
        stix2.v21.UserAccount, 'x-some-extension-ext', [
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
        @stix2.v21.CustomExtension(
            Foo, 'x-new-ext', [
                ('property1', stix2.properties.StringProperty(required=True)),
            ],
        )
        class FooExtension():
            pass  # pragma: no cover
    assert str(excinfo.value) == "'observable' must be a valid Observable class!"

    class Bar(stix2.v21.observables._Observable):
        pass
    with pytest.raises(ValueError) as excinfo:
        @stix2.v21.CustomExtension(
            Bar, 'x-new-ext', [
                ('property1', stix2.properties.StringProperty(required=True)),
            ],
        )
        class BarExtension():
            pass
    assert "Unknown observable type" in str(excinfo.value)
    assert "Custom observables must be created with the @CustomObservable decorator." in str(excinfo.value)

    class Baz(stix2.v21.observables._Observable):
        _type = 'Baz'
    with pytest.raises(ValueError) as excinfo:
        @stix2.v21.CustomExtension(
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
        @stix2.v21.CustomExtension(
            stix2.v21.File, 'x', {
                'property1': stix2.properties.StringProperty(required=True),
            },
        )
        class FooExtension():
            pass  # pragma: no cover
    assert "Invalid type name 'x':" in str(excinfo.value)

    with pytest.raises(ValueError) as excinfo:
        @stix2.v21.CustomExtension(
            stix2.v21.File, 'x_new_ext', {
                'property1': stix2.properties.StringProperty(required=True),
            },
        )
        class BlaExtension():
            pass  # pragma: no cover
    assert "Invalid type name 'x_new_ext':" in str(excinfo.value)

    with pytest.raises(ValueError) as excinfo:
        @stix2.v21.CustomExtension(
            stix2.v21.File, '7x-new-ext', {
                'property1': stix2.properties.StringProperty(required=True),
            },
        )
        class Bla2Extension():
            pass  # pragma: no cover
    assert "Invalid type name '7x-new-ext':" in str(excinfo.value)


def test_custom_extension_no_properties():
    with pytest.raises(ValueError):
        @stix2.v21.CustomExtension(stix2.v21.DomainName, 'x-new2-ext', None)
        class BarExtension():
            pass


def test_custom_extension_empty_properties():
    with pytest.raises(ValueError):
        @stix2.v21.CustomExtension(stix2.v21.DomainName, 'x-new2-ext', [])
        class BarExtension():
            pass


def test_custom_extension_dict_properties():
    with pytest.raises(ValueError):
        @stix2.v21.CustomExtension(stix2.v21.DomainName, 'x-new2-ext', {})
        class BarExtension():
            pass


def test_custom_extension_no_init_1():
    @stix2.v21.CustomExtension(
        stix2.v21.DomainName, 'x-new-extension-ext', [
            ('property1', stix2.properties.StringProperty(required=True)),
        ],
    )
    class NewExt():
        pass

    ne = NewExt(property1="foobar")
    assert ne.property1 == "foobar"


def test_custom_extension_no_init_2():
    @stix2.v21.CustomExtension(
        stix2.v21.DomainName, 'x-new2-ext', [
            ('property1', stix2.properties.StringProperty(required=True)),
        ],
    )
    class NewExt2(object):
        pass

    ne2 = NewExt2(property1="foobar")
    assert ne2.property1 == "foobar"


def test_invalid_custom_property_in_extension():
    with pytest.raises(ValueError) as excinfo:
        @stix2.v21.CustomExtension(
            stix2.v21.DomainName, 'x-new3-ext', [
                ('6property1', stix2.properties.StringProperty(required=True)),
            ],
        )
        class NewExt():
            pass

    assert "must begin with an alpha character." in str(excinfo.value)


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
    parsed = stix2.parse(input_str, version='2.1')
    assert parsed.extensions['x-new-ext'].property2 == 12


def test_custom_and_spec_extension_mix():
    """
    Try to make sure that when allow_custom=True, encountering a custom
    extension doesn't result in a completely uncleaned extensions property.
    """

    file_obs = stix2.v21.File(
        name="my_file.dat",
        extensions={
            "x-custom1-ext": {
                "a": 1,
                "b": 2,
            },
            "ntfs-ext": {
                "sid": "S-1-whatever",
            },
            "x-custom2-ext": {
                "z": 99.9,
                "y": False,
            },
            "raster-image-ext": {
                "image_height": 1024,
                "image_width": 768,
                "bits_per_pixel": 32,
            },
        },
        allow_custom=True,
    )

    assert file_obs.extensions["x-custom1-ext"] == {"a": 1, "b": 2}
    assert file_obs.extensions["x-custom2-ext"] == {"y": False, "z": 99.9}
    assert file_obs.extensions["ntfs-ext"].sid == "S-1-whatever"
    assert file_obs.extensions["raster-image-ext"].image_height == 1024

    # Both of these should have been converted to objects, not left as dicts.
    assert isinstance(
        file_obs.extensions["raster-image-ext"], stix2.v21.RasterImageExt,
    )
    assert isinstance(
        file_obs.extensions["ntfs-ext"], stix2.v21.NTFSExt,
    )


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
    with pytest.raises(InvalidValueError) as excinfo:
        stix2.parse(data, version='2.1')
    assert "Can't parse unknown extension type" in str(excinfo.value)
    parsed_ob = stix2.parse(data, allow_custom=True, version='2.1')
    assert parsed_ob['extensions']['x-foobar-ext']['property1'] == 'foo'
    assert not isinstance(parsed_ob['extensions']['x-foobar-ext'], stix2.base._STIXBase)


def test_register_custom_object():
    # Not the way to register custom object.
    class CustomObject2(object):
        _type = 'awesome-object'

    with pytest.raises(ValueError) as excinfo:
        stix2.parsing._register_object(CustomObject2, version="2.1")
    assert '@CustomObject decorator' in str(excinfo)


def test_extension_property_location():
    assert 'extensions' in stix2.v21.OBJ_MAP_OBSERVABLE['x-new-observable']._properties
    assert 'extensions' not in stix2.v21.EXT_MAP['domain-name']['x-new-ext']._properties


@pytest.mark.parametrize(
    "data", [
        """{
    "type": "x-example",
    "spec_version": "2.1",
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
    @stix2.v21.CustomObject(
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


@stix2.v21.CustomObject(
    'x-new-type-2', [
        ('property1', stix2.properties.StringProperty()),
        ('property2', stix2.properties.IntegerProperty()),
    ],
)
class NewType3(object):
    pass


def test_register_custom_object_with_version():
    custom_obj_1 = {
        "type": "x-new-type-2",
        "id": "x-new-type-2--00000000-0000-4000-8000-000000000007",
        "spec_version": "2.1",
    }

    cust_obj_1 = stix2.parsing.dict_to_stix2(custom_obj_1, version='2.1')
    v = 'v21'

    assert cust_obj_1.type in stix2.parsing.STIX2_OBJ_MAPS[v]['objects']
    assert cust_obj_1.spec_version == "2.1"


def test_register_duplicate_object_with_version():
    with pytest.raises(DuplicateRegistrationError) as excinfo:
        @stix2.v21.CustomObject(
            'x-new-type-2', [
                ('property1', stix2.properties.StringProperty()),
                ('property2', stix2.properties.IntegerProperty()),
            ],
        )
        class NewType2(object):
            pass
    assert "cannot be registered again" in str(excinfo.value)


@stix2.v21.CustomObservable(
    'x-new-observable-3', [
        ('property1', stix2.properties.StringProperty()),
    ],
)
class NewObservable3(object):
    pass


def test_register_observable():
    custom_obs = NewObservable3(property1="Test Observable")
    v = 'v21'

    assert custom_obs.type in stix2.parsing.STIX2_OBJ_MAPS[v]['observables']


def test_register_duplicate_observable():
    with pytest.raises(DuplicateRegistrationError) as excinfo:
        @stix2.v21.CustomObservable(
            'x-new-observable-2', [
                ('property1', stix2.properties.StringProperty()),
            ],
        )
        class NewObservable2(object):
            pass
    assert "cannot be registered again" in str(excinfo.value)


def test_register_observable_custom_extension():
    @stix2.v21.CustomExtension(
        stix2.v21.DomainName, 'x-new-2-ext', [
            ('property1', stix2.properties.StringProperty(required=True)),
            ('property2', stix2.properties.IntegerProperty()),
        ],
    )
    class NewExtension2():
        pass

    example = NewExtension2(property1="Hi there")
    v = 'v21'

    assert 'domain-name' in stix2.parsing.STIX2_OBJ_MAPS[v]['observables']
    assert example._type in stix2.parsing.STIX2_OBJ_MAPS[v]['observable-extensions']['domain-name']


def test_register_duplicate_observable_extension():
    with pytest.raises(DuplicateRegistrationError) as excinfo:
        @stix2.v21.CustomExtension(
            stix2.v21.DomainName, 'x-new-2-ext', [
                ('property1', stix2.properties.StringProperty(required=True)),
                ('property2', stix2.properties.IntegerProperty()),
            ],
        )
        class NewExtension2():
            pass
    assert "cannot be registered again" in str(excinfo.value)


def test_register_duplicate_marking():
    with pytest.raises(DuplicateRegistrationError) as excinfo:
        @stix2.v21.CustomMarking(
            'x-new-obj', [
                ('property1', stix2.properties.StringProperty(required=True)),
            ],
        )
        class NewObj2():
            pass
    assert "cannot be registered again" in str(excinfo.value)
