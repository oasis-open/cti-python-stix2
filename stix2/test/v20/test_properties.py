import uuid

import pytest

import stix2
from stix2.exceptions import AtLeastOnePropertyError, DictionaryKeyError
from stix2.properties import (
    ERROR_INVALID_ID, BinaryProperty, BooleanProperty, DictionaryProperty,
    EmbeddedObjectProperty, EnumProperty, ExtensionsProperty, FloatProperty,
    HashesProperty, HexProperty, IDProperty, IntegerProperty, ListProperty,
    Property, ReferenceProperty, STIXObjectProperty, StringProperty,
    TimestampProperty, TypeProperty,
)
from stix2.v20.common import MarkingProperty

from . import constants


def test_property():
    p = Property()

    assert p.required is False
    assert p.clean('foo') == 'foo'
    assert p.clean(3) == 3


def test_basic_clean():
    class Prop(Property):

        def clean(self, value):
            if value == 42:
                return value
            else:
                raise ValueError("Must be 42")

    p = Prop()

    assert p.clean(42) == 42
    with pytest.raises(ValueError):
        p.clean(41)


def test_property_default():
    class Prop(Property):

        def default(self):
            return 77

    p = Prop()

    assert p.default() == 77


def test_fixed_property():
    p = Property(fixed="2.0")

    assert p.clean("2.0")
    with pytest.raises(ValueError):
        assert p.clean("x") is False
    with pytest.raises(ValueError):
        assert p.clean(2.0) is False

    assert p.default() == "2.0"
    assert p.clean(p.default())


def test_list_property():
    p = ListProperty(StringProperty)

    assert p.clean(['abc', 'xyz'])
    with pytest.raises(ValueError):
        p.clean([])


def test_string_property():
    prop = StringProperty()

    assert prop.clean('foobar')
    assert prop.clean(1)
    assert prop.clean([1, 2, 3])


def test_type_property():
    prop = TypeProperty('my-type')

    assert prop.clean('my-type')
    with pytest.raises(ValueError):
        prop.clean('not-my-type')
    assert prop.clean(prop.default())


ID_PROP = IDProperty('my-type')
MY_ID = 'my-type--232c9d3f-49fc-4440-bb01-607f638778e7'


@pytest.mark.parametrize(
    "value", [
        MY_ID,
        'my-type--00000000-0000-4000-8000-000000000000',
    ],
)
def test_id_property_valid(value):
    assert ID_PROP.clean(value) == value


CONSTANT_IDS = [
    constants.ATTACK_PATTERN_ID,
    constants.CAMPAIGN_ID,
    constants.COURSE_OF_ACTION_ID,
    constants.IDENTITY_ID,
    constants.INDICATOR_ID,
    constants.INTRUSION_SET_ID,
    constants.MALWARE_ID,
    constants.MARKING_DEFINITION_ID,
    constants.OBSERVED_DATA_ID,
    constants.RELATIONSHIP_ID,
    constants.REPORT_ID,
    constants.SIGHTING_ID,
    constants.THREAT_ACTOR_ID,
    constants.TOOL_ID,
    constants.VULNERABILITY_ID,
]
CONSTANT_IDS.extend(constants.MARKING_IDS)
CONSTANT_IDS.extend(constants.RELATIONSHIP_IDS)


@pytest.mark.parametrize("value", CONSTANT_IDS)
def test_id_property_valid_for_type(value):
    type = value.split('--', 1)[0]
    assert IDProperty(type=type).clean(value) == value


def test_id_property_wrong_type():
    with pytest.raises(ValueError) as excinfo:
        ID_PROP.clean('not-my-type--232c9d3f-49fc-4440-bb01-607f638778e7')
    assert str(excinfo.value) == "must start with 'my-type--'."


@pytest.mark.parametrize(
    "value", [
        'my-type--foo',
        # Not a v4 UUID
        'my-type--00000000-0000-0000-0000-000000000000',
        'my-type--' + str(uuid.uuid1()),
        'my-type--' + str(uuid.uuid3(uuid.NAMESPACE_DNS, "example.org")),
        'my-type--' + str(uuid.uuid5(uuid.NAMESPACE_DNS, "example.org")),
    ],
)
def test_id_property_not_a_valid_hex_uuid(value):
    with pytest.raises(ValueError) as excinfo:
        ID_PROP.clean(value)
    assert str(excinfo.value) == ERROR_INVALID_ID


def test_id_property_default():
    default = ID_PROP.default()
    assert ID_PROP.clean(default) == default


@pytest.mark.parametrize(
    "value", [
        2,
        -1,
        3.14,
        False,
    ],
)
def test_integer_property_valid(value):
    int_prop = IntegerProperty()
    assert int_prop.clean(value) is not None


@pytest.mark.parametrize(
    "value", [
        -1,
        -100,
        -5 * 6,
    ],
)
def test_integer_property_invalid_min_with_constraints(value):
    int_prop = IntegerProperty(min=0, max=180)
    with pytest.raises(ValueError) as excinfo:
        int_prop.clean(value)
    assert "minimum value is" in str(excinfo.value)


@pytest.mark.parametrize(
    "value", [
        181,
        200,
        50 * 6,
    ],
)
def test_integer_property_invalid_max_with_constraints(value):
    int_prop = IntegerProperty(min=0, max=180)
    with pytest.raises(ValueError) as excinfo:
        int_prop.clean(value)
    assert "maximum value is" in str(excinfo.value)


@pytest.mark.parametrize(
    "value", [
        "something",
        StringProperty(),
    ],
)
def test_integer_property_invalid(value):
    int_prop = IntegerProperty()
    with pytest.raises(ValueError):
        int_prop.clean(value)


@pytest.mark.parametrize(
    "value", [
        2,
        -1,
        3.14,
        False,
    ],
)
def test_float_property_valid(value):
    int_prop = FloatProperty()
    assert int_prop.clean(value) is not None


@pytest.mark.parametrize(
    "value", [
        "something",
        StringProperty(),
    ],
)
def test_float_property_invalid(value):
    int_prop = FloatProperty()
    with pytest.raises(ValueError):
        int_prop.clean(value)


@pytest.mark.parametrize(
    "value", [
        True,
        False,
        'True',
        'False',
        'true',
        'false',
        'TRUE',
        'FALSE',
        'T',
        'F',
        't',
        'f',
        1,
        0,
    ],
)
def test_boolean_property_valid(value):
    bool_prop = BooleanProperty()

    assert bool_prop.clean(value) is not None


@pytest.mark.parametrize(
    "value", [
        'abc',
        ['false'],
        {'true': 'true'},
        2,
        -1,
    ],
)
def test_boolean_property_invalid(value):
    bool_prop = BooleanProperty()
    with pytest.raises(ValueError):
        bool_prop.clean(value)


def test_reference_property():
    ref_prop = ReferenceProperty()

    assert ref_prop.clean("my-type--00000000-0000-4000-8000-000000000000")
    with pytest.raises(ValueError):
        ref_prop.clean("foo")

    # This is not a valid V4 UUID
    with pytest.raises(ValueError):
        ref_prop.clean("my-type--00000000-0000-0000-0000-000000000000")


@pytest.mark.parametrize(
    "value", [
        '2017-01-01T12:34:56Z',
        '2017-01-01 12:34:56',
        'Jan 1 2017 12:34:56',
    ],
)
def test_timestamp_property_valid(value):
    ts_prop = TimestampProperty()
    assert ts_prop.clean(value) == constants.FAKE_TIME


def test_timestamp_property_invalid():
    ts_prop = TimestampProperty()
    with pytest.raises(ValueError):
        ts_prop.clean(1)
    with pytest.raises(ValueError):
        ts_prop.clean("someday sometime")


def test_binary_property():
    bin_prop = BinaryProperty()

    assert bin_prop.clean("TG9yZW0gSXBzdW0=")
    with pytest.raises(ValueError):
        bin_prop.clean("foobar")


def test_hex_property():
    hex_prop = HexProperty()

    assert hex_prop.clean("4c6f72656d20497073756d")
    with pytest.raises(ValueError):
        hex_prop.clean("foobar")


@pytest.mark.parametrize(
    "d", [
        {'description': 'something'},
        [('abc', 1), ('bcd', 2), ('cde', 3)],
    ],
)
def test_dictionary_property_valid(d):
    dict_prop = DictionaryProperty()
    assert dict_prop.clean(d)


@pytest.mark.parametrize(
    "d", [
        [{'a': 'something'}, "Invalid dictionary key a: (shorter than 3 characters)."],
        [
            {'a'*300: 'something'}, "Invalid dictionary key aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            "aaaaaaaaaaaaaaaaaaaaaaa: (longer than 256 characters).",
        ],
        [
            {'Hey!': 'something'}, "Invalid dictionary key Hey!: (contains characters other than lowercase a-z, "
            "uppercase A-Z, numerals 0-9, hyphen (-), or underscore (_)).",
        ],
    ],
)
def test_dictionary_property_invalid_key(d):
    dict_prop = DictionaryProperty()

    with pytest.raises(DictionaryKeyError) as excinfo:
        dict_prop.clean(d[0])

    assert str(excinfo.value) == d[1]


@pytest.mark.parametrize(
    "d", [
        # TODO: This error message could be made more helpful. The error is caused
        # because `json.loads()` doesn't like the *single* quotes around the key
        # name, even though they are valid in a Python dictionary. While technically
        # accurate (a string is not a dictionary), if we want to be able to load
        # string-encoded "dictionaries" that are, we need a better error message
        # or an alternative to `json.loads()` ... and preferably *not* `eval()`. :-)
        # Changing the following to `'{"description": "something"}'` does not cause
        # any ValueError to be raised.
        ("{'description': 'something'}", "The dictionary property must contain a dictionary"),
    ],
)
def test_dictionary_property_invalid(d):
    dict_prop = DictionaryProperty()

    with pytest.raises(ValueError) as excinfo:
        dict_prop.clean(d[0])
    assert str(excinfo.value) == d[1]


def test_property_list_of_dictionary():
    @stix2.v20.CustomObject(
        'x-new-obj', [
            ('property1', ListProperty(DictionaryProperty(), required=True)),
        ],
    )
    class NewObj():
        pass

    test_obj = NewObj(property1=[{'foo': 'bar'}])
    assert test_obj.property1[0]['foo'] == 'bar'


@pytest.mark.parametrize(
    "value", [
        {"sha256": "6db12788c37247f2316052e142f42f4b259d6561751e5f401a1ae2a6df9c674b"},
        [('MD5', '2dfb1bcc980200c6706feee399d41b3f'), ('RIPEMD-160', 'b3a8cd8a27c90af79b3c81754f267780f443dfef')],
    ],
)
def test_hashes_property_valid(value):
    hash_prop = HashesProperty()
    assert hash_prop.clean(value)


@pytest.mark.parametrize(
    "value", [
        {"MD5": "a"},
        {"SHA-256": "2dfb1bcc980200c6706feee399d41b3f"},
    ],
)
def test_hashes_property_invalid(value):
    hash_prop = HashesProperty()

    with pytest.raises(ValueError):
        hash_prop.clean(value)


def test_embedded_property():
    emb_prop = EmbeddedObjectProperty(type=stix2.v20.EmailMIMEComponent)
    mime = stix2.v20.EmailMIMEComponent(
        content_type="text/plain; charset=utf-8",
        content_disposition="inline",
        body="Cats are funny!",
    )
    assert emb_prop.clean(mime)

    with pytest.raises(ValueError):
        emb_prop.clean("string")


@pytest.mark.parametrize(
    "value", [
        ['a', 'b', 'c'],
        ('a', 'b', 'c'),
        'b',
    ],
)
def test_enum_property_valid(value):
    enum_prop = EnumProperty(value)
    assert enum_prop.clean('b')


def test_enum_property_invalid():
    enum_prop = EnumProperty(['a', 'b', 'c'])
    with pytest.raises(ValueError):
        enum_prop.clean('z')


def test_extension_property_valid():
    ext_prop = ExtensionsProperty(enclosing_type='file')
    assert ext_prop({
        'windows-pebinary-ext': {
            'pe_type': 'exe',
        },
    })


@pytest.mark.parametrize(
    "data", [
        1,
        {'foobar-ext': {
            'pe_type': 'exe',
        }},
    ],
)
def test_extension_property_invalid(data):
    ext_prop = ExtensionsProperty(enclosing_type='file')
    with pytest.raises(ValueError):
        ext_prop.clean(data)


def test_extension_property_invalid_type():
    ext_prop = ExtensionsProperty(enclosing_type='indicator')
    with pytest.raises(ValueError) as excinfo:
        ext_prop.clean(
            {
                'windows-pebinary-ext': {
                    'pe_type': 'exe',
                },
            },
        )
    assert "Can't parse unknown extension" in str(excinfo.value)


def test_extension_at_least_one_property_constraint():
    with pytest.raises(AtLeastOnePropertyError):
        stix2.v20.TCPExt()


def test_marking_property_error():
    mark_prop = MarkingProperty()

    with pytest.raises(ValueError) as excinfo:
        mark_prop.clean('my-marking')

    assert str(excinfo.value) == "must be a Statement, TLP Marking or a registered marking."


def test_stix_property_not_compliant_spec():
    # This is a 2.0 test only...
    indicator = stix2.v20.Indicator(spec_version="2.0", allow_custom=True, **constants.INDICATOR_KWARGS)
    stix_prop = STIXObjectProperty(spec_version="2.0")

    with pytest.raises(ValueError) as excinfo:
        stix_prop.clean(indicator)

    assert "Spec version 2.0 bundles don't yet support containing objects of a different spec version." in str(excinfo.value)
