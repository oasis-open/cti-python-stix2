import contextlib
import uuid

import pytest

import stix2
import stix2.base
import stix2.registration
import stix2.registry
import stix2.v21

from ...exceptions import (
    DuplicateRegistrationError, InvalidValueError, MissingPropertiesError,
)
from .constants import FAKE_TIME, IDENTITY_ID, MARKING_DEFINITION_ID

# Custom Properties in SDOs

IDENTITY_CUSTOM_PROP = stix2.v21.Identity(
    name="John Smith",
    identity_class="individual",
    x_foo="bar",
    allow_custom=True,
)


@contextlib.contextmanager
def _register_extension(ext, props):
    """
    A contextmanager useful for registering an extension and then ensuring
    it gets unregistered again.  A random extension-definition STIX ID is
    generated for the extension and yielded as the contextmanager's value.

    :param ext: The class which would normally be decorated with the
        CustomExtension decorator.
    :param props: Properties as would normally be passed into the
        CustomExtension decorator.
    """

    ext_def_id = "extension-definition--" + str(uuid.uuid4())

    stix2.v21.CustomExtension(
        ext_def_id,
        props,
    )(ext)

    try:
        yield ext_def_id
    finally:
        # "unregister" the extension
        del stix2.registry.STIX2_OBJ_MAPS["2.1"]["extensions"][ext_def_id]


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
    with pytest.raises(InvalidValueError):
        stix2.v21.Bundle(custom_identity)

    bundle = stix2.v21.Bundle(custom_identity, allow_custom=True)
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
        allow_custom=True,
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


def test_custom_object_ref_property_containing_identifier():
    @stix2.v21.CustomObject(
        'x-new-obj-with-ref', [
            ('property_ref', stix2.properties.ReferenceProperty(invalid_types=[])),
        ],
    )
    class NewObs():
        pass


def test_custom_object_refs_property_containing_identifiers():
    @stix2.v21.CustomObject(
        'x-new-obj-with-refs', [
            ('property_refs', stix2.properties.ListProperty(stix2.properties.ReferenceProperty(invalid_types=[]))),
        ],
    )
    class NewObs():
        pass


def test_custom_object_ref_property_containing_objectref():
    with pytest.raises(ValueError, match=r"not a subclass of 'ReferenceProperty"):
        @stix2.v21.CustomObject(
            'x-new-obj-with-objref', [
                ('property_ref', stix2.properties.ObjectReferenceProperty()),
            ],
        )
        class NewObs():
            pass


def test_custom_object_refs_property_containing_objectrefs():
    with pytest.raises(ValueError, match=r"not a 'ListProperty' containing a subclass of 'ReferenceProperty"):
        @stix2.v21.CustomObject(
            'x-new-obj-with-objrefs', [
                ('property_refs', stix2.properties.ListProperty(stix2.properties.ObjectReferenceProperty())),
            ],
        )
        class NewObs():
            pass


def test_custom_object_invalid_ref_property():
    with pytest.raises(ValueError) as excinfo:
        @stix2.v21.CustomObject(
            'x-new-obj', [
                ('property_ref', stix2.properties.StringProperty()),
            ],
        )
        class NewObs():
            pass
    assert "is named like a reference property but is not" in str(excinfo.value)


def test_custom_object_invalid_refs_property():
    with pytest.raises(ValueError) as excinfo:
        @stix2.v21.CustomObject(
            'x-new-obj', [
                ('property_refs', stix2.properties.StringProperty()),
            ],
        )
        class NewObs():
            pass
    assert "is named like a reference list property but is not" in str(excinfo.value)


def test_custom_object_invalid_refs_list_property():
    with pytest.raises(ValueError) as excinfo:
        @stix2.v21.CustomObject(
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
        "id": "bundle--78d99c4a-4eda-4c59-b264-60807f05d799",
        "objects": [
            {
                "type": "identity",
                "spec_version": "2.1",
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
    ident = stix2.v21.Identity(
        name="alice", identity_class=123, x_foo=123, allow_custom=True,
    )

    obj_dict = {
        "type": "bundle",
        "id": "bundle--78d99c4a-4eda-4c59-b264-60807f05d799",
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


def test_custom_observable_object_ref_property_as_identifier():
    @stix2.v21.CustomObservable(
        'x-new-obs-with-ref', [
            ('property_ref', stix2.properties.ReferenceProperty(invalid_types=[])),
        ],
    )
    class NewObs():
        pass


def test_custom_observable_object_refs_property_containing_identifiers():
    @stix2.v21.CustomObservable(
        'x-new-obs-with-refs', [
            ('property_refs', stix2.properties.ListProperty(stix2.properties.ReferenceProperty(invalid_types=[]))),
        ],
    )
    class NewObs():
        pass


def test_custom_observable_object_ref_property_as_objectref():
    with pytest.raises(ValueError, match=r"not a subclass of 'ReferenceProperty"):
        @stix2.v21.CustomObservable(
            'x-new-obs-with-objref', [
                ('property_ref', stix2.properties.ObjectReferenceProperty()),
            ],
        )
        class NewObs():
            pass


def test_custom_observable_object_refs_property_containing_objectrefs():
    with pytest.raises(ValueError, match=r"not a 'ListProperty' containing a subclass of 'ReferenceProperty"):
        @stix2.v21.CustomObservable(
            'x-new-obs-with-objrefs', [
                ('property_refs', stix2.properties.ListProperty(stix2.properties.ObjectReferenceProperty())),
            ],
        )
        class NewObs():
            pass


def test_custom_observable_object_invalid_ref_property():
    with pytest.raises(ValueError) as excinfo:
        @stix2.v21.CustomObservable(
            'x-new-obs', [
                ('property_ref', stix2.properties.StringProperty()),
            ],
        )
        class NewObs():
            pass
    assert "is named like a reference property but is not" in str(excinfo.value)


def test_custom_observable_object_invalid_refs_property():
    with pytest.raises(ValueError) as excinfo:
        @stix2.v21.CustomObservable(
            'x-new-obs', [
                ('property_refs', stix2.properties.StringProperty()),
            ],
        )
        class NewObs():
            pass
    assert "is named like a reference list property but is not" in str(excinfo.value)


def test_custom_observable_object_invalid_refs_list_property():
    with pytest.raises(ValueError) as excinfo:
        @stix2.v21.CustomObservable(
            'x-new-obs', [
                ('property_refs', stix2.properties.ListProperty(stix2.properties.StringProperty)),
            ],
        )
        class NewObs():
            pass
    assert "is named like a reference list property but is not" in str(excinfo.value)


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
        stix2.v21.File(
            name="abc.txt",
            extensions={
                "ntfs-ext": ext,
            },
        )

    assert "Can't create extension 'ntfs-ext'" in excinfo.value.reason


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
        'x-some-extension-ext', [
                ('keys', stix2.properties.ListProperty(stix2.properties.DictionaryProperty, required=True)),
        ],
    )
    class SomeCustomExtension:
        pass

    example = SomeCustomExtension(keys=[{'test123': 123, 'test345': 'aaaa'}])
    assert data == example.serialize(pretty=True)


def test_custom_extension_invalid_type_name():
    with pytest.raises(ValueError) as excinfo:
        @stix2.v21.CustomExtension(
            'x', {
                    'property1': stix2.properties.StringProperty(required=True),
            },
        )
        class FooExtension():
            pass  # pragma: no cover
    assert "Invalid type name 'x':" in str(excinfo.value)

    with pytest.raises(ValueError) as excinfo:
        @stix2.v21.CustomExtension(
            'x_new_ext', {
                    'property1': stix2.properties.StringProperty(required=True),
            },
        )
        class BlaExtension():
            pass  # pragma: no cover
    assert "Invalid type name 'x_new_ext':" in str(excinfo.value)

    with pytest.raises(ValueError) as excinfo:
        @stix2.v21.CustomExtension(
            '7x-new-ext', {
                    'property1': stix2.properties.StringProperty(required=True),
            },
        )
        class Bla2Extension():
            pass  # pragma: no cover
    assert "Invalid type name '7x-new-ext':" in str(excinfo.value)


def test_custom_extension_no_properties():
    with pytest.raises(ValueError):
        @stix2.v21.CustomExtension('x-new2-ext', None)
        class BarExtension():
            pass


def test_custom_extension_empty_properties():
    with pytest.raises(ValueError):
        @stix2.v21.CustomExtension('x-new2-ext', [])
        class BarExtension():
            pass


def test_custom_extension_dict_properties():
    with pytest.raises(ValueError):
        @stix2.v21.CustomExtension('x-new2-ext', {})
        class BarExtension():
            pass


def test_custom_extension_no_init_1():
    @stix2.v21.CustomExtension(
        'x-new-extension-ext', [
                ('property1', stix2.properties.StringProperty(required=True)),
        ],
    )
    class NewExt():
        pass

    ne = NewExt(property1="foobar")
    assert ne.property1 == "foobar"


def test_custom_extension_no_init_2():
    @stix2.v21.CustomExtension(
        'x-new2-ext', [
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
            'x-new3-ext', [
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


def test_parse_observable_with_custom_extension_property():
    input_str = """{
        "type": "observed-data",
        "spec_version": "2.1",
        "first_observed": "1976-09-09T01:50:24.000Z",
        "last_observed": "1988-01-18T15:22:10.000Z",
        "number_observed": 5,
        "objects": {
            "0": {
                "type": "file",
                "spec_version": "2.1",
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

    parsed = stix2.parse(input_str, version='2.1', allow_custom=True)
    assert parsed.has_custom
    assert parsed["objects"]["0"]["extensions"]["raster-image-ext"]["x-foo"] is False

    with pytest.raises(InvalidValueError):
        stix2.parse(input_str, version="2.1", allow_custom=False)


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


def test_unregistered_new_style_extension():

    f_dict = {
        "type": "file",
        "name": "foo.txt",
        "extensions": {
            "extension-definition--31adb724-a9a4-44b6-8ec2-fd4b181c9507": {
                "extension-type": "property-extension",
                "a": 1,
                "b": True,
            },
        },
    }

    f = stix2.parse(f_dict, allow_custom=False)

    assert f.extensions[
        "extension-definition--31adb724-a9a4-44b6-8ec2-fd4b181c9507"
    ]["a"] == 1
    assert f.extensions[
        "extension-definition--31adb724-a9a4-44b6-8ec2-fd4b181c9507"
    ]["b"]
    assert not f.has_custom

    f = stix2.parse(f_dict, allow_custom=True)

    assert f.extensions[
        "extension-definition--31adb724-a9a4-44b6-8ec2-fd4b181c9507"
    ]["a"] == 1
    assert f.extensions[
        "extension-definition--31adb724-a9a4-44b6-8ec2-fd4b181c9507"
    ]["b"]
    assert not f.has_custom


def test_register_custom_object():
    # Not the way to register custom object.
    class CustomObject2(object):
        _type = 'awesome-object'

    with pytest.raises(ValueError) as excinfo:
        stix2.registration._register_object(CustomObject2, version="2.1")
    assert '@CustomObject decorator' in str(excinfo)


def test_extension_property_location():
    assert 'extensions' in stix2.v21.OBJ_MAP_OBSERVABLE['x-new-observable']._properties
    assert 'extensions' not in stix2.v21.EXT_MAP['x-new-ext']._properties


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

    assert data == example.serialize(pretty=True)


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

    assert cust_obj_1.type in stix2.registry.STIX2_OBJ_MAPS['2.1']['objects']
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

    assert custom_obs.type in stix2.registry.STIX2_OBJ_MAPS['2.1']['observables']


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
        'x-new-2-ext', [
                ('property1', stix2.properties.StringProperty(required=True)),
                ('property2', stix2.properties.IntegerProperty()),
        ],
    )
    class NewExtension2():
        pass

    example = NewExtension2(property1="Hi there")

    assert 'domain-name' in stix2.registry.STIX2_OBJ_MAPS['2.1']['observables']
    assert example._type in stix2.registry.STIX2_OBJ_MAPS['2.1']['extensions']


def test_register_duplicate_observable_extension():
    with pytest.raises(DuplicateRegistrationError) as excinfo:
        @stix2.v21.CustomExtension(
            'x-new-2-ext', [
                    ('property1', stix2.properties.StringProperty(required=True)),
                    ('property2', stix2.properties.IntegerProperty()),
            ],
        )
        class NewExtension2():
            pass
    assert "cannot be registered again" in str(excinfo.value)


def test_unregistered_top_level_extension_passes_with_allow_custom_false():
    indicator = stix2.v21.Indicator(
        id='indicator--e97bfccf-8970-4a3c-9cd1-5b5b97ed5d0c',
        created='2014-02-20T09:16:08.989000Z',
        modified='2014-02-20T09:16:08.989000Z',
        name='File hash for Poison Ivy variant',
        description='This file hash indicates that a sample of Poison Ivy is present.',
        labels=[
            'malicious-activity',
        ],
        rank=5,
        toxicity=8,
        pattern='[file:hashes.\'SHA-256\' = \'ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c\']',
        pattern_type='stix',
        valid_from='2014-02-20T09:00:00.000000Z',
        extensions={
            'extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e': {
                'extension_type': 'toplevel-property-extension',
            },
        },
        allow_custom=False,
    )
    assert indicator.rank == 5
    assert indicator.toxicity == 8
    assert indicator.extensions['extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e']['extension_type'] == 'toplevel-property-extension'
    assert isinstance(indicator.extensions['extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e'], dict)


def test_unregistered_embedded_extension_passes_with_allow_custom_false():
    indicator = stix2.v21.Indicator(
        id='indicator--e97bfccf-8970-4a3c-9cd1-5b5b97ed5d0c',
        created='2014-02-20T09:16:08.989000Z',
        modified='2014-02-20T09:16:08.989000Z',
        name='File hash for Poison Ivy variant',
        description='This file hash indicates that a sample of Poison Ivy is present.',
        labels=[
            'malicious-activity',
        ],
        pattern='[file:hashes.\'SHA-256\' = \'ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c\']',
        pattern_type='stix',
        valid_from='2014-02-20T09:00:00.000000Z',
        extensions={
            'extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e': {
                'extension_type': 'property-extension',
                'rank': 5,
                'toxicity': 8,
            },
        },
        allow_custom=False,
    )
    assert indicator.extensions['extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e']['rank'] == 5
    assert indicator.extensions['extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e']['toxicity'] == 8
    assert indicator.extensions['extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e']['extension_type'] == 'property-extension'
    assert isinstance(indicator.extensions['extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e'], dict)


def test_registered_top_level_extension_passes_with_allow_custom_false():
    @stix2.v21.CustomExtension(
        'extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e', [
            ('rank', stix2.properties.IntegerProperty(required=True)),
            ('toxicity', stix2.properties.IntegerProperty(required=True)),
        ],
    )
    class ExtensionFoo1:
        extension_type = 'toplevel-property-extension'

    indicator = stix2.v21.Indicator(
        id='indicator--e97bfccf-8970-4a3c-9cd1-5b5b97ed5d0c',
        created='2014-02-20T09:16:08.989000Z',
        modified='2014-02-20T09:16:08.989000Z',
        name='File hash for Poison Ivy variant',
        description='This file hash indicates that a sample of Poison Ivy is present.',
        labels=[
            'malicious-activity',
        ],
        rank=5,
        toxicity=8,
        pattern='[file:hashes.\'SHA-256\' = \'ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c\']',
        pattern_type='stix',
        valid_from='2014-02-20T09:00:00.000000Z',
        extensions={
            'extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e': {
                'extension_type': 'toplevel-property-extension',
            },
        },
        allow_custom=False,
    )
    assert indicator.rank == 5
    assert indicator.toxicity == 8
    assert indicator.extensions['extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e']['extension_type'] == 'toplevel-property-extension'
    assert isinstance(indicator.extensions['extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e'], ExtensionFoo1)


def test_registered_embedded_extension_passes_with_allow_custom_false():
    @stix2.v21.CustomExtension(
        'extension-definition--d83fce45-ef58-4c6c-a3ff-1fbc32e98c6e', [
            ('rank', stix2.properties.IntegerProperty(required=True)),
            ('toxicity', stix2.properties.IntegerProperty(required=True)),
        ],
    )
    class ExtensionFoo1:
        extension_type = "property-extension"

    indicator = stix2.v21.Indicator(
        id='indicator--e97bfccf-8970-4a3c-9cd1-5b5b97ed5d0c',
        created='2014-02-20T09:16:08.989000Z',
        modified='2014-02-20T09:16:08.989000Z',
        name='File hash for Poison Ivy variant',
        description='This file hash indicates that a sample of Poison Ivy is present.',
        labels=[
            'malicious-activity',
        ],
        pattern='[file:hashes.\'SHA-256\' = \'ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c\']',
        pattern_type='stix',
        valid_from='2014-02-20T09:00:00.000000Z',
        extensions={
            'extension-definition--d83fce45-ef58-4c6c-a3ff-1fbc32e98c6e': {
                'extension_type': 'property-extension',
                'rank': 5,
                'toxicity': 8,
            },
        },
        allow_custom=False,
    )
    assert indicator.extensions['extension-definition--d83fce45-ef58-4c6c-a3ff-1fbc32e98c6e']['rank'] == 5
    assert indicator.extensions['extension-definition--d83fce45-ef58-4c6c-a3ff-1fbc32e98c6e']['toxicity'] == 8
    assert indicator.extensions['extension-definition--d83fce45-ef58-4c6c-a3ff-1fbc32e98c6e']['extension_type'] == 'property-extension'
    assert isinstance(indicator.extensions['extension-definition--d83fce45-ef58-4c6c-a3ff-1fbc32e98c6e'], ExtensionFoo1)


def test_registered_new_extension_sdo_allow_custom_false():
    @stix2.v21.CustomObject(
        'my-favorite-sdo', [
            ('name', stix2.properties.StringProperty(required=True)),
            ('some_property_name1', stix2.properties.StringProperty(required=True)),
            ('some_property_name2', stix2.properties.StringProperty()),
        ], 'extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e9999',
    )
    class MyFavSDO:
        pass

    my_favorite_sdo = {
        'type': 'my-favorite-sdo',
        'spec_version': '2.1',
        'id': 'my-favorite-sdo--c5ba9dba-5ad9-4bbe-9825-df4cb8675774',
        'created': '2014-02-20T09:16:08.989000Z',
        'modified': '2014-02-20T09:16:08.989000Z',
        'name': 'This is the name of my favorite',
        'some_property_name1': 'value1',
        'some_property_name2': 'value2',
        # 'extensions': {
        #     'extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e9999': ExtensionDefinitiond83fce45ef584c6ca3f41fbc32e98c6e()
        # }
    }
    sdo_object = stix2.parse(my_favorite_sdo)
    assert isinstance(sdo_object, MyFavSDO)
    assert isinstance(
        sdo_object.extensions['extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e9999'],
        stix2.v21.EXT_MAP['extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e9999'],
    )

    sdo_serialized = sdo_object.serialize()
    assert '"extensions": {"extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e9999": {"extension_type": "new-sdo"}}' in sdo_serialized


def test_registered_new_extension_sro_allow_custom_false():
    @stix2.v21.CustomObject(
        'my-favorite-sro', [
            ('name', stix2.properties.StringProperty(required=True)),
            ('some_property_name1', stix2.properties.StringProperty(required=True)),
            ('some_property_name2', stix2.properties.StringProperty()),
        ], 'extension-definition--e96690a5-dc13-4f27-99dd-0f2188ad74ce', False,
    )
    class MyFavSRO:
        pass

    my_favorite_sro = {
        'type': 'my-favorite-sro',
        'spec_version': '2.1',
        'id': 'my-favorite-sro--c5ba9dba-5ad9-4bbe-9825-df4cb8675774',
        'created': '2014-02-20T09:16:08.989000Z',
        'modified': '2014-02-20T09:16:08.989000Z',
        'name': 'This is the name of my favorite',
        'some_property_name1': 'value1',
        'some_property_name2': 'value2',
        # 'extensions': {
        #     'extension-definition--e96690a5-dc13-4f27-99dd-0f2188ad74ce': ExtensionDefinitiond83fce45ef584c6ca3f41fbc32e98c6e()
        # }
    }
    sro_object = stix2.parse(my_favorite_sro)
    assert isinstance(sro_object, MyFavSRO)
    assert isinstance(
        sro_object.extensions['extension-definition--e96690a5-dc13-4f27-99dd-0f2188ad74ce'],
        stix2.v21.EXT_MAP['extension-definition--e96690a5-dc13-4f27-99dd-0f2188ad74ce'],
    )

    sdo_serialized = sro_object.serialize()
    assert '"extensions": {"extension-definition--e96690a5-dc13-4f27-99dd-0f2188ad74ce": {"extension_type": "new-sro"}}' in sdo_serialized


def test_registered_new_extension_sco_allow_custom_false():
    @stix2.v21.CustomObservable(
        'my-favorite-sco', [
            ('name', stix2.properties.StringProperty(required=True)),
            ('some_network_protocol_field', stix2.properties.StringProperty(required=True)),
        ], ['name', 'some_network_protocol_field'], 'extension-definition--a932fcc6-e032-177c-126f-cb970a5a1fff',
    )
    class MyFavSCO:
        pass

    my_favorite_sco = {
        'type': 'my-favorite-sco',
        'spec_version': '2.1',
        'id': 'my-favorite-sco--f9dbe89c-0030-4a9d-8b78-0dcd0a0de874',
        'name': 'This is the name of my favorite SCO',
        'some_network_protocol_field': 'value',
        # 'extensions': {
        #     'extension-definition--a932fcc6-e032-177c-126f-cb970a5a1fff': {
        #         'is_extension_so': true
        #     }
        # }
    }

    sco_object = stix2.parse(my_favorite_sco)
    assert isinstance(sco_object, MyFavSCO)
    assert isinstance(
        sco_object.extensions['extension-definition--a932fcc6-e032-177c-126f-cb970a5a1fff'],
        stix2.v21.EXT_MAP['extension-definition--a932fcc6-e032-177c-126f-cb970a5a1fff'],
    )

    sco_serialized = sco_object.serialize()
    assert '"extensions": {"extension-definition--a932fcc6-e032-177c-126f-cb970a5a1fff": {"extension_type": "new-sco"}}' in sco_serialized


def test_registered_new_extension_marking_allow_custom_false():

    class MyFavMarking:
        extension_type = "property-extension"

    props = {
        'some_marking_field': stix2.properties.StringProperty(required=True),
    }

    with _register_extension(MyFavMarking, props) as ext_def_id:

        my_favorite_marking = {
            'type': 'marking-definition',
            'spec_version': '2.1',
            'id': 'marking-definition--f9dbe89c-0030-4a9d-8b78-0dcd0a0de874',
            'name': 'This is the name of my favorite Marking',
            'extensions': {
                ext_def_id: {
                    'extension_type': 'property-extension',
                    'some_marking_field': 'value',
                },
            },
        }

        marking_object = stix2.parse(my_favorite_marking)
        assert isinstance(marking_object, stix2.v21.MarkingDefinition)
        assert isinstance(
            marking_object.extensions[ext_def_id],
            stix2.v21.EXT_MAP[ext_def_id],
        )

        marking_serialized = marking_object.serialize(sort_keys=True)
        assert '"extensions": {{"{}": ' \
               '{{"extension_type": "property-extension", "some_marking_field": "value"}}}}'.format(ext_def_id) in marking_serialized


def test_custom_marking_toplevel_properties():
    class CustomMarking:
        extension_type = "toplevel-property-extension"

    props = {
        "foo": stix2.properties.StringProperty(required=True),
    }

    with _register_extension(CustomMarking, props) as ext_def_id:

        marking_dict = {
            "type": "marking-definition",
            "spec_version": "2.1",
            "foo": "hello",
            "extensions": {
                ext_def_id: {
                    "extension_type": "toplevel-property-extension",
                },
            },
        }

        marking = stix2.parse(marking_dict)
        assert marking.foo == "hello"


def test_nested_ext_prop_meta():

    class TestExt:
        extension_type = "property-extension"

    props = {
        "intprop": stix2.properties.IntegerProperty(required=True),
        "strprop": stix2.properties.StringProperty(
            required=False, default=lambda: "foo",
        ),
    }

    with _register_extension(TestExt, props) as ext_def_id:

        obj = stix2.v21.Identity(
            name="test",
            extensions={
                ext_def_id: {
                    "extension_type": "property-extension",
                    "intprop": "1",
                    "strprop": 2,
                },
            },
        )

        assert obj.extensions[ext_def_id].extension_type == "property-extension"
        assert obj.extensions[ext_def_id].intprop == 1
        assert obj.extensions[ext_def_id].strprop == "2"

        obj = stix2.v21.Identity(
            name="test",
            extensions={
                ext_def_id: {
                    "extension_type": "property-extension",
                    "intprop": "1",
                },
            },
        )

        # Ensure default kicked in
        assert obj.extensions[ext_def_id].strprop == "foo"

        with pytest.raises(InvalidValueError):
            stix2.v21.Identity(
                name="test",
                extensions={
                    ext_def_id: {
                        "extension_type": "property-extension",
                        # wrong value type
                        "intprop": "foo",
                    },
                },
            )

        with pytest.raises(InvalidValueError):
            stix2.v21.Identity(
                name="test",
                extensions={
                    ext_def_id: {
                        "extension_type": "property-extension",
                        # missing required property
                        "strprop": "foo",
                    },
                },
            )

        with pytest.raises(InvalidValueError):
            stix2.v21.Identity(
                name="test",
                extensions={
                    ext_def_id: {
                        "extension_type": "property-extension",
                        "intprop": 1,
                        # Use of undefined property
                        "foo": False,
                    },
                },
            )

        with pytest.raises(InvalidValueError):
            stix2.v21.Identity(
                name="test",
                extensions={
                    ext_def_id: {
                        # extension_type doesn't match with registration
                        "extension_type": "new-sdo",
                        "intprop": 1,
                        "strprop": "foo",
                    },
                },
            )


def test_toplevel_ext_prop_meta():

    class TestExt:
        extension_type = "toplevel-property-extension"

    props = {
        "intprop": stix2.properties.IntegerProperty(required=True),
        "strprop": stix2.properties.StringProperty(
            required=False, default=lambda: "foo",
        ),
    }

    with _register_extension(TestExt, props) as ext_def_id:

        obj = stix2.v21.Identity(
            name="test",
            intprop="1",
            strprop=2,
            extensions={
                ext_def_id: {
                    "extension_type": "toplevel-property-extension",
                },
            },
        )

        assert obj.extensions[ext_def_id].extension_type == "toplevel-property-extension"
        assert obj.intprop == 1
        assert obj.strprop == "2"

        obj = stix2.v21.Identity(
            name="test",
            intprop=1,
            extensions={
                ext_def_id: {
                    "extension_type": "toplevel-property-extension",
                },
            },
        )

        # Ensure default kicked in
        assert obj.strprop == "foo"

        with pytest.raises(InvalidValueError):
            stix2.v21.Identity(
                name="test",
                intprop="foo",  # wrong value type
                extensions={
                    ext_def_id: {
                        "extension_type": "toplevel-property-extension",
                    },
                },
            )

        with pytest.raises(InvalidValueError):
            stix2.v21.Identity(
                name="test",
                intprop=1,
                extensions={
                    ext_def_id: {
                        "extension_type": "toplevel-property-extension",
                        # Use of undefined property
                        "foo": False,
                    },
                },
            )

        with pytest.raises(InvalidValueError):
            stix2.v21.Identity(
                name="test",
                intprop=1,
                extensions={
                    ext_def_id: {
                        "extension_type": "toplevel-property-extension",
                        # Use of a defined property, but intended for the
                        # top level.  This should still error out.
                        "strprop": 1,
                    },
                },
            )

        with pytest.raises(MissingPropertiesError):
            stix2.v21.Identity(
                name="test",
                strprop="foo",  # missing required property
                extensions={
                    ext_def_id: {
                        "extension_type": "toplevel-property-extension",
                    },
                },
            )


def test_toplevel_extension_includes_extensions():
    """
    Test whether the library allows an extension to enable extension support
    itself. :)  I.e. a toplevel property extension which adds the "extensions"
    property.
    """

    class ExtensionsExtension:
        extension_type = "toplevel-property-extension"

    ext_props = {
        "extensions": stix2.properties.ExtensionsProperty(spec_version="2.1"),
    }

    with _register_extension(ExtensionsExtension, ext_props) as ext_id:

        # extension-definition is not defined with an "extensions" property.
        obj_dict = {
            "type": "extension-definition",
            "spec_version": "2.1",
            "created_by_ref": "identity--8a1fd5dd-4586-4ded-bd39-04bda62f8415",
            "name": "my extension",
            "version": "1.2.3",
            "schema": "add extension support to an object!",
            "extension_types": ["toplevel-property-extension"],
            "extensions": {
                ext_id: {
                    "extension_type": "toplevel-property-extension",
                },
            },
        }

        stix2.parse(obj_dict)


def test_invalid_extension_prop_name():

    with pytest.raises(ValueError):
        @stix2.v21.common.CustomExtension(
            "extension-definition--0530fdbd-0fa3-42ab-90cf-660e0abad370",
            [
                ("7foo", stix2.properties.StringProperty()),
            ],
        )
        class CustomExt:
            extension_type = "property-extension"

    with pytest.raises(ValueError):
        @stix2.v21.common.CustomExtension(
            "extension-definition--0530fdbd-0fa3-42ab-90cf-660e0abad370",
            [
                ("7foo", stix2.properties.StringProperty()),
            ],
        )
        class CustomExt:  # noqa: F811
            extension_type = "toplevel-property-extension"


def test_allow_custom_propagation():
    obj_dict = {
        "type": "bundle",
        "objects": [
            {
                "type": "file",
                "spec_version": "2.1",
                "name": "data.dat",
                "extensions": {
                    "archive-ext": {
                        "contains_refs": [
                            "file--3d4da5f6-31d8-4a66-a172-f31af9bf5238",
                            "file--4bb16def-cdfc-40d1-b6a4-815de6c60b74",
                        ],
                        "x_foo": "bar",
                    },
                },
            },
        ],
    }

    # allow_custom=False at the top level should catch the custom property way
    # down in the SCO extension.
    with pytest.raises(InvalidValueError):
        stix2.parse(obj_dict, allow_custom=False)
