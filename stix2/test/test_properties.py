import pytest

from stix2 import EmailMIMEComponent, ExtensionsProperty, TCPExt
from stix2.exceptions import AtLeastOnePropertyError, DictionaryKeyError
from stix2.properties import (BinaryProperty, BooleanProperty,
                              DictionaryProperty, EmbeddedObjectProperty,
                              EnumProperty, FloatProperty, HashesProperty,
                              HexProperty, IDProperty, IntegerProperty,
                              ListProperty, Property, ReferenceProperty,
                              StringProperty, TimestampProperty, TypeProperty)

from .constants import FAKE_TIME


def test_property():
    p = Property()

    assert p.required is False


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


def test_id_property():
    idprop = IDProperty('my-type')

    assert idprop.clean('my-type--90aaca8a-1110-5d32-956d-ac2f34a1bd8c')
    with pytest.raises(ValueError) as excinfo:
        idprop.clean('not-my-type--90aaca8a-1110-5d32-956d-ac2f34a1bd8c')
    assert str(excinfo.value) == "must start with 'my-type--'."
    with pytest.raises(ValueError) as excinfo:
        idprop.clean('my-type--foo')
    assert str(excinfo.value) == "must have a valid UUID after the prefix."

    assert idprop.clean(idprop.default())


@pytest.mark.parametrize("value", [
    2,
    -1,
    3.14,
    False,
])
def test_integer_property_valid(value):
    int_prop = IntegerProperty()
    assert int_prop.clean(value) is not None


@pytest.mark.parametrize("value", [
    "something",
    StringProperty(),
])
def test_integer_property_invalid(value):
    int_prop = IntegerProperty()
    with pytest.raises(ValueError):
        int_prop.clean(value)


@pytest.mark.parametrize("value", [
    2,
    -1,
    3.14,
    False,
])
def test_float_property_valid(value):
    int_prop = FloatProperty()
    assert int_prop.clean(value) is not None


@pytest.mark.parametrize("value", [
    "something",
    StringProperty(),
])
def test_float_property_invalid(value):
    int_prop = FloatProperty()
    with pytest.raises(ValueError):
        int_prop.clean(value)


@pytest.mark.parametrize("value", [
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
])
def test_boolean_property_valid(value):
    bool_prop = BooleanProperty()

    assert bool_prop.clean(value) is not None


@pytest.mark.parametrize("value", [
    'abc',
    ['false'],
    {'true': 'true'},
    2,
    -1,
])
def test_boolean_property_invalid(value):
    bool_prop = BooleanProperty()
    with pytest.raises(ValueError):
        bool_prop.clean(value)


def test_reference_property():
    ref_prop = ReferenceProperty()

    assert ref_prop.clean("my-type--3a331bfe-0566-55e1-a4a0-9a2cd355a300")
    with pytest.raises(ValueError):
        ref_prop.clean("foo")


@pytest.mark.parametrize("value", [
    '2017-01-01T12:34:56Z',
    '2017-01-01 12:34:56',
    'Jan 1 2017 12:34:56',
])
def test_timestamp_property_valid(value):
    ts_prop = TimestampProperty()
    assert ts_prop.clean(value) == FAKE_TIME


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


@pytest.mark.parametrize("d", [
    {'description': 'something'},
    [('abc', 1), ('bcd', 2), ('cde', 3)],
])
def test_dictionary_property_valid(d):
    dict_prop = DictionaryProperty()
    assert dict_prop.clean(d)


@pytest.mark.parametrize("d", [
    [{'a': 'something'}, "Invalid dictionary key a: (shorter than 3 characters)."],
    [{'a'*300: 'something'}, "Invalid dictionary key aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                             "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                             "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                             "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                             "aaaaaaaaaaaaaaaaaaaaaaa: (longer than 256 characters)."],
    [{'Hey!': 'something'}, "Invalid dictionary key Hey!: (contains characters other thanlowercase a-z, "
                            "uppercase A-Z, numerals 0-9, hyphen (-), or underscore (_))."],
])
def test_dictionary_property_invalid_key(d):
    dict_prop = DictionaryProperty()

    with pytest.raises(DictionaryKeyError) as excinfo:
        dict_prop.clean(d[0])

    assert str(excinfo.value) == d[1]


@pytest.mark.parametrize("d", [
    ({}, "The dictionary property must contain a non-empty dictionary"),
    # TODO: This error message could be made more helpful. The error is caused
    # because `json.loads()` doesn't like the *single* quotes around the key
    # name, even though they are valid in a Python dictionary. While technically
    # accurate (a string is not a dictionary), if we want to be able to load
    # string-encoded "dictionaries" that are, we need a better error message
    # or an alternative to `json.loads()` ... and preferably *not* `eval()`. :-)
    # Changing the following to `'{"description": "something"}'` does not cause
    # any ValueError to be raised.
    ("{'description': 'something'}", "The dictionary property must contain a dictionary"),
])
def test_dictionary_property_invalid(d):
    dict_prop = DictionaryProperty()

    with pytest.raises(ValueError) as excinfo:
        dict_prop.clean(d[0])
    assert str(excinfo.value) == d[1]


@pytest.mark.parametrize("value", [
    {"sha256": "6db12788c37247f2316052e142f42f4b259d6561751e5f401a1ae2a6df9c674b"},
    [('MD5', '2dfb1bcc980200c6706feee399d41b3f'), ('RIPEMD-160', 'b3a8cd8a27c90af79b3c81754f267780f443dfef')],
])
def test_hashes_property_valid(value):
    hash_prop = HashesProperty()
    assert hash_prop.clean(value)


@pytest.mark.parametrize("value", [
    {"MD5": "a"},
    {"SHA-256": "2dfb1bcc980200c6706feee399d41b3f"},
])
def test_hashes_property_invalid(value):
    hash_prop = HashesProperty()

    with pytest.raises(ValueError):
        hash_prop.clean(value)


def test_embedded_property():
    emb_prop = EmbeddedObjectProperty(type=EmailMIMEComponent)
    mime = EmailMIMEComponent(
        content_type="text/plain; charset=utf-8",
        content_disposition="inline",
        body="Cats are funny!"
    )
    assert emb_prop.clean(mime)

    with pytest.raises(ValueError):
        emb_prop.clean("string")


@pytest.mark.parametrize("value", [
    ['a', 'b', 'c'],
    ('a', 'b', 'c'),
    'b',
])
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
            'pe_type': 'exe'
        },
    })


@pytest.mark.parametrize("data", [
    1,
    {'foobar-ext': {
        'pe_type': 'exe'
    }},
])
def test_extension_property_invalid(data):
    ext_prop = ExtensionsProperty(enclosing_type='file')
    with pytest.raises(ValueError):
        ext_prop.clean(data)


def test_extension_property_invalid_type():
    ext_prop = ExtensionsProperty(enclosing_type='indicator')
    with pytest.raises(ValueError) as excinfo:
        ext_prop.clean({
            'windows-pebinary-ext': {
                'pe_type': 'exe'
            }}
        )
    assert 'no extensions defined' in str(excinfo.value)


def test_extension_at_least_one_property_constraint():
    with pytest.raises(AtLeastOnePropertyError):
        TCPExt()
