import pytest

import stix2
import stix2.parsing
import stix2.registration
import stix2.registry
import stix2.v20

from ...exceptions import DuplicateRegistrationError, InvalidValueError
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
    assert issubclass(excinfo.value.cls, stix2.v20.Identity)
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
    with pytest.raises(InvalidValueError):
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

    # must not succeed: allow_custom was not set to True when creating
    # the bundle, so it must reject the customized identity object.
    with pytest.raises(InvalidValueError):
        stix2.v20.Bundle(custom_identity)


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
        allow_custom=True,
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
    with pytest.raises(InvalidValueError):
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


def test_register_duplicate_marking():
    with pytest.raises(DuplicateRegistrationError) as excinfo:
        @stix2.v20.CustomMarking(
            'x-new-obj2', [
                ('property1', stix2.properties.StringProperty(required=True)),
            ],
        )
        class NewObj2():
            pass
    assert "cannot be registered again" in str(excinfo.value)


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


def test_custom_object_ref_property_as_identifier():
    @stix2.v20.CustomObject(
        'x-new-obj-with-ref', [
            ('property_ref', stix2.properties.ReferenceProperty(invalid_types=[])),
        ],
    )
    class NewObs():
        pass


def test_custom_object_refs_property_containing_identifiers():
    @stix2.v20.CustomObject(
        'x-new-obj-with-refs', [
            ('property_refs', stix2.properties.ListProperty(stix2.properties.ReferenceProperty(invalid_types=[]))),
        ],
    )
    class NewObs():
        pass


def test_custom_object_ref_property_as_objectref():
    with pytest.raises(ValueError, match=r"not a subclass of 'ReferenceProperty"):
        @stix2.v20.CustomObject(
            'x-new-obj-with-objref', [
                ('property_ref', stix2.properties.ObjectReferenceProperty()),
            ],
        )
        class NewObs():
            pass


def test_custom_object_refs_property_containing_objectrefs():
    with pytest.raises(ValueError, match=r"not a 'ListProperty' containing a subclass of 'ReferenceProperty"):
        @stix2.v20.CustomObject(
            'x-new-obj-with-objrefs', [
                ('property_refs', stix2.properties.ListProperty(stix2.properties.ObjectReferenceProperty())),
            ],
        )
        class NewObs():
            pass


def test_custom_object_invalid_ref_property():
    with pytest.raises(ValueError) as excinfo:
        @stix2.v20.CustomObject(
            'x-new-obj', [
                ('property_ref', stix2.properties.StringProperty()),
            ],
        )
        class NewObs():
            pass
    assert "is named like a reference property but is not" in str(excinfo.value)


def test_custom_object_invalid_refs_property():
    with pytest.raises(ValueError) as excinfo:
        @stix2.v20.CustomObject(
            'x-new-obj', [
                ('property_refs', stix2.properties.StringProperty()),
            ],
        )
        class NewObs():
            pass
    assert "is named like a reference list property but is not" in str(excinfo.value)


def test_custom_object_invalid_refs_list_property():
    with pytest.raises(ValueError) as excinfo:
        @stix2.v20.CustomObject(
            'x-new-obj', [
                ('property_refs', stix2.properties.ListProperty(stix2.properties.StringProperty)),
            ],
        )
        class NewObs():
            pass
    assert "is named like a reference list property but is not" in str(excinfo.value)


def test_custom_subobject_dict():
    obj_dict = {
        "type": "bundle",
        "spec_version": "2.0",
        "objects": [
            {
                "type": "identity",
                "name": "alice",
                "identity_class": "individual",
                "x_foo": 123,
            },
        ],
    }

    obj = stix2.parse(obj_dict, allow_custom=True)
    assert obj["objects"][0]["x_foo"] == 123
    assert obj.has_custom

    with pytest.raises(InvalidValueError):
        stix2.parse(obj_dict, allow_custom=False)


def test_custom_subobject_obj():
    ident = stix2.v20.Identity(
        name="alice", identity_class=123, x_foo=123, allow_custom=True,
    )

    obj_dict = {
        "type": "bundle",
        "spec_version": "2.0",
        "objects": [ident],
    }

    obj = stix2.parse(obj_dict, allow_custom=True)
    assert obj["objects"][0]["x_foo"] == 123
    assert obj.has_custom

    with pytest.raises(InvalidValueError):
        stix2.parse(obj_dict, allow_custom=False)


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
    no = NewObservable(
        property1='something',
        extensions={
            'archive-ext': stix2.v20.observables.ArchiveExt(
                contains_refs=['file--e277603e-1060-5ad4-9937-c26c97f1ca68'],
                version='2.0',
                comment='for real',
            ),
        },
    )
    assert no.property1 == 'something'
    assert no.extensions['archive-ext'].comment == 'for real'


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
        'x-new-observable-1', [
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
    assert "Invalid type name 'x':" in str(excinfo.value)

    with pytest.raises(ValueError) as excinfo:
        @stix2.v20.CustomObservable(
            'x_new_obs', [
                ('property1', stix2.properties.StringProperty()),
            ],
        )
        class NewObs2(object):
            pass  # pragma: no cover
    assert "Invalid type name 'x_new_obs':" in str(excinfo.value)


def test_custom_observable_object_ref_property_as_identifier():
    with pytest.raises(ValueError, match=r"not a subclass of 'ObjectReferenceProperty"):
        @stix2.v20.CustomObservable(
            'x-new-obs-with-ref', [
                ('property_ref', stix2.properties.ReferenceProperty(invalid_types=[])),
            ],
        )
        class NewObs():
            pass


def test_custom_observable_object_refs_property_containing_identifiers():
    with pytest.raises(ValueError, match=r"not a 'ListProperty' containing a subclass of 'ObjectReferenceProperty"):
        @stix2.v20.CustomObservable(
            'x-new-obs-with-refs', [
                ('property_refs', stix2.properties.ListProperty(stix2.properties.ReferenceProperty(invalid_types=[]))),
            ],
        )
        class NewObs():
            pass


def test_custom_observable_object_ref_property_as_objectref():
    @stix2.v20.CustomObservable(
        'x-new-obs-with-objref', [
            ('property_ref', stix2.properties.ObjectReferenceProperty()),
        ],
    )
    class NewObs():
        pass


def test_custom_observable_object_refs_property_containing_objectrefs():
    @stix2.v20.CustomObservable(
        'x-new-obs-with-objrefs', [
            ('property_refs', stix2.properties.ListProperty(stix2.properties.ObjectReferenceProperty())),
        ],
    )
    class NewObs():
        pass


def test_custom_observable_object_invalid_ref_property():
    with pytest.raises(ValueError) as excinfo:
        @stix2.v20.CustomObservable(
            'x-new-obs', [
                ('property_ref', stix2.properties.StringProperty()),
            ],
        )
        class NewObs():
            pass
    assert "is named like a reference property but is not" in str(excinfo.value)


def test_custom_observable_object_invalid_refs_property():
    with pytest.raises(ValueError) as excinfo:
        @stix2.v20.CustomObservable(
            'x-new-obs', [
                ('property_refs', stix2.properties.StringProperty()),
            ],
        )
        class NewObs():
            pass
    assert "is named like a reference list property but is not" in str(excinfo.value)


def test_custom_observable_object_invalid_refs_list_property():
    with pytest.raises(ValueError) as excinfo:
        @stix2.v20.CustomObservable(
            'x-new-obs', [
                ('property_refs', stix2.properties.ListProperty(stix2.properties.StringProperty)),
            ],
        )
        class NewObs():
            pass
    assert "is named like a reference list property but is not" in str(excinfo.value)


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

    with pytest.raises(stix2.exceptions.ParseError) as excinfo:
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
    'x-new-ext', [
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
    assert str(excinfo.value) == "No values for required properties for NewExtension: (property1)."

    with pytest.raises(ValueError) as excinfo:
        NewExtension(property1='something', property2=4)
    assert str(excinfo.value) == "'property2' is too small."


def test_custom_extension_wrong_observable_type():
    # NewExtension is an extension of DomainName, not File
    ext = NewExtension(property1='something')
    with pytest.raises(InvalidValueError) as excinfo:
        stix2.v20.File(
            name="abc.txt",
            extensions={
                "ntfs-ext": ext,
            },
        )

    assert "Can't create extension 'ntfs-ext' from" in excinfo.value.reason


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
        'some-extension', [
                ('keys', stix2.properties.ListProperty(stix2.properties.DictionaryProperty, required=True)),
        ],
    )
    class SomeCustomExtension:
        pass

    example = SomeCustomExtension(keys=[{'test123': 123, 'test345': 'aaaa'}])
    assert data == example.serialize(pretty=True)


def test_custom_extension_invalid_type_name():
    with pytest.raises(ValueError) as excinfo:
        @stix2.v20.CustomExtension(
            'x', {
                    'property1': stix2.properties.StringProperty(required=True),
            },
        )
        class FooExtension():
            pass  # pragma: no cover
    assert "Invalid type name 'x':" in str(excinfo.value)

    with pytest.raises(ValueError) as excinfo:
        @stix2.v20.CustomExtension(
            'x_new_ext', {
                    'property1': stix2.properties.StringProperty(required=True),
            },
        )
        class BlaExtension():
            pass  # pragma: no cover
    assert "Invalid type name 'x_new_ext':" in str(excinfo.value)


def test_custom_extension_no_properties():
    with pytest.raises(ValueError):
        @stix2.v20.CustomExtension('x-new-ext2', None)
        class BarExtension():
            pass


def test_custom_extension_empty_properties():
    with pytest.raises(ValueError):
        @stix2.v20.CustomExtension('x-new-ext2', [])
        class BarExtension():
            pass


def test_custom_extension_dict_properties():
    with pytest.raises(ValueError):
        @stix2.v20.CustomExtension('x-new-ext2', {})
        class BarExtension():
            pass


def test_custom_extension_no_init_1():
    @stix2.v20.CustomExtension(
        'x-new-extension', [
                ('property1', stix2.properties.StringProperty(required=True)),
        ],
    )
    class NewExt():
        pass

    ne = NewExt(property1="foobar")
    assert ne.property1 == "foobar"


def test_custom_extension_no_init_2():
    @stix2.v20.CustomExtension(
        'x-new-ext2', [
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


def test_parse_observable_with_custom_extension_property():
    input_str = """{
        "type": "observed-data",
        "first_observed": "1976-09-09T01:50:24.000Z",
        "last_observed": "1988-01-18T15:22:10.000Z",
        "number_observed": 5,
        "objects": {
            "0": {
                "type": "file",
                "name": "cats.png",
                "extensions": {
                    "raster-image-ext": {
                        "image_height": 1024,
                        "image_width": 768,
                        "x-foo": false
                    }
                }
            }
        }
    }"""

    parsed = stix2.parse(input_str, version='2.0', allow_custom=True)
    assert parsed.has_custom
    assert parsed["objects"]["0"]["extensions"]["raster-image-ext"]["x-foo"] is False

    with pytest.raises(InvalidValueError):
        stix2.parse(input_str, version="2.0", allow_custom=False)


def test_custom_and_spec_extension_mix():
    """
    Try to make sure that when allow_custom=True, encountering a custom
    extension doesn't result in a completely uncleaned extensions property.
    """

    file_obs = stix2.v20.File(
        name="my_file.dat",
        extensions={
            "x-custom1": {
                "a": 1,
                "b": 2,
            },
            "ntfs-ext": {
                "sid": "S-1-whatever",
            },
            "x-custom2": {
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

    assert file_obs.extensions["x-custom1"] == {"a": 1, "b": 2}
    assert file_obs.extensions["x-custom2"] == {"y": False, "z": 99.9}
    assert file_obs.extensions["ntfs-ext"].sid == "S-1-whatever"
    assert file_obs.extensions["raster-image-ext"].image_height == 1024

    # Both of these should have been converted to objects, not left as dicts.
    assert isinstance(
        file_obs.extensions["raster-image-ext"], stix2.v20.RasterImageExt,
    )
    assert isinstance(
        file_obs.extensions["ntfs-ext"], stix2.v20.NTFSExt,
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
        stix2.parse_observable(data, version='2.0')
    assert "Can't parse unknown extension type" in str(excinfo.value)

    parsed_ob = stix2.parse_observable(data, allow_custom=True, version='2.0')
    assert parsed_ob['extensions']['x-foobar-ext']['property1'] == 'foo'
    assert not isinstance(parsed_ob['extensions']['x-foobar-ext'], stix2.base._STIXBase)


def test_register_custom_object():
    # Not the way to register custom object.
    class CustomObject2(object):
        _type = 'awesome-object'

    with pytest.raises(ValueError):
        stix2.registration._register_object(CustomObject2, version="2.0")


def test_extension_property_location():
    assert 'extensions' in stix2.v20.OBJ_MAP_OBSERVABLE['x-new-observable']._properties
    assert 'extensions' not in stix2.v20.EXT_MAP['x-new-ext']._properties


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

    assert data == example.serialize(pretty=True)


@stix2.v20.CustomObject(
    'x-new-type-2', [
        ('property1', stix2.properties.StringProperty()),
        ('property2', stix2.properties.IntegerProperty()),
    ],
)
class NewType2(object):
    pass


def test_register_custom_object_with_version():
    custom_obj_1 = {
        "type": "x-new-type-2",
        "id": "x-new-type-2--00000000-0000-4000-8000-000000000007",
    }

    cust_obj_1 = stix2.parsing.dict_to_stix2(custom_obj_1, version='2.0')

    assert cust_obj_1.type in stix2.registry.STIX2_OBJ_MAPS['2.0']['objects']
    # spec_version is not in STIX 2.0, and is required in 2.1, so this
    # suffices as a test for a STIX 2.0 object.
    assert "spec_version" not in cust_obj_1


def test_register_duplicate_object_with_version():
    with pytest.raises(DuplicateRegistrationError) as excinfo:
        @stix2.v20.CustomObject(
            'x-new-type-2', [
                ('property1', stix2.properties.StringProperty()),
                ('property2', stix2.properties.IntegerProperty()),
            ],
        )
        class NewType2(object):
            pass
    assert "cannot be registered again" in str(excinfo.value)


@stix2.v20.CustomObservable(
    'x-new-observable-2', [
        ('property1', stix2.properties.StringProperty()),
    ],
)
class NewObservable2(object):
    pass


def test_register_observable_with_version():
    custom_obs = NewObservable2(property1="Test Observable")

    assert custom_obs.type in stix2.registry.STIX2_OBJ_MAPS['2.0']['observables']


def test_register_duplicate_observable_with_version():
    with pytest.raises(DuplicateRegistrationError) as excinfo:
        @stix2.v20.CustomObservable(
            'x-new-observable-2', [
                ('property1', stix2.properties.StringProperty()),
            ],
        )
        class NewObservable2(object):
            pass
    assert "cannot be registered again" in str(excinfo.value)


def test_register_marking_with_version():
    @stix2.v20.CustomMarking(
        'x-new-obj-2', [
            ('property1', stix2.properties.StringProperty(required=True)),
        ],
    )
    class NewObj2():
        pass

    no = NewObj2(property1='something')
    assert no._type in stix2.registry.STIX2_OBJ_MAPS['2.0']['markings']


def test_register_observable_extension_with_version():
    @stix2.v20.CustomExtension(
        'some-extension-2', [
                ('keys', stix2.properties.StringProperty(required=True)),
        ],
    )
    class SomeCustomExtension2:
        pass

    example = SomeCustomExtension2(keys='test123')

    assert example._type in stix2.registry.STIX2_OBJ_MAPS['2.0']['extensions']


def test_register_duplicate_observable_extension():
    with pytest.raises(DuplicateRegistrationError) as excinfo:
        @stix2.v20.CustomExtension(
            'some-extension-2', [
                    ('property1', stix2.properties.StringProperty(required=True)),
                    ('property2', stix2.properties.IntegerProperty()),
            ],
        )
        class NewExtension2():
            pass
    assert "cannot be registered again" in str(excinfo.value)
