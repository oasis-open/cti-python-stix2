import pytest

import stix2
from stix2.exceptions import (
    AtLeastOnePropertyError, CustomContentError, DictionaryKeyError,
)
from stix2.properties import (
    DictionaryProperty, EmbeddedObjectProperty, ExtensionsProperty,
    HashesProperty, IDProperty, ListProperty, ReferenceProperty,
    StringProperty, TypeProperty,
)
from stix2.v21.common import MarkingProperty

from . import constants


def test_dictionary_property():
    p = DictionaryProperty(StringProperty)

    assert p.clean({'spec_version': '2.1'})
    with pytest.raises(ValueError):
        p.clean({})


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


ID_PROP = IDProperty('my-type', spec_version="2.1")
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
    assert IDProperty(type=type, spec_version="2.1").clean(value) == value


def test_id_property_wrong_type():
    with pytest.raises(ValueError) as excinfo:
        ID_PROP.clean('not-my-type--232c9d3f-49fc-4440-bb01-607f638778e7')
    assert str(excinfo.value) == "must start with 'my-type--'."


@pytest.mark.parametrize(
    "value", [
        'my-type--foo',
        # Not a RFC 4122 UUID
        'my-type--00000000-0000-0000-0000-000000000000',
    ],
)
def test_id_property_not_a_valid_hex_uuid(value):
    with pytest.raises(ValueError):
        ID_PROP.clean(value)


def test_id_property_default():
    default = ID_PROP.default()
    assert ID_PROP.clean(default) == default


def test_reference_property():
    ref_prop = ReferenceProperty(valid_types="my-type", spec_version="2.1")

    assert ref_prop.clean("my-type--00000000-0000-4000-8000-000000000000")
    with pytest.raises(ValueError):
        ref_prop.clean("foo")

    # This is not a valid RFC 4122 UUID
    with pytest.raises(ValueError):
        ref_prop.clean("my-type--00000000-0000-0000-0000-000000000000")


def test_reference_property_specific_type():
    ref_prop = ReferenceProperty(valid_types="my-type", spec_version="2.1")

    with pytest.raises(ValueError):
        ref_prop.clean("not-my-type--8a8e8758-f92c-4058-ba38-f061cd42a0cf")

    assert ref_prop.clean("my-type--8a8e8758-f92c-4058-ba38-f061cd42a0cf") == \
        "my-type--8a8e8758-f92c-4058-ba38-f061cd42a0cf"


@pytest.mark.parametrize(
    "d", [
        {'description': 'something'},
        [('abc', 1), ('bcd', 2), ('cde', 3)],
    ],
)
def test_dictionary_property_valid(d):
    dict_prop = DictionaryProperty(spec_version='2.1')
    assert dict_prop.clean(d)


@pytest.mark.parametrize(
    "d", [
        [{'a': 'something'}, "Invalid dictionary key a: (shorter than 3 characters)."],
    ],
)
def test_dictionary_no_longer_raises(d):
    dict_prop = DictionaryProperty(spec_version='2.1')
    dict_prop.clean(d[0])


@pytest.mark.parametrize(
    "d", [
        [
            {'a'*300: 'something'}, "Invalid dictionary key aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            "aaaaaaaaaaaaaaaaaaaaaaa: (longer than 250 characters).",
        ],
        [
            {'Hey!': 'something'}, "Invalid dictionary key Hey!: (contains characters other than lowercase a-z, "
            "uppercase A-Z, numerals 0-9, hyphen (-), or underscore (_)).",
        ],
    ],
)
def test_dictionary_property_invalid_key(d):
    dict_prop = DictionaryProperty(spec_version='2.1')

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
    dict_prop = DictionaryProperty(spec_version='2.1')

    with pytest.raises(ValueError) as excinfo:
        dict_prop.clean(d[0])
    assert str(excinfo.value) == d[1]


def test_property_list_of_dictionary():
    @stix2.v21.CustomObject(
        'x-new-obj-4', [
            ('property1', ListProperty(DictionaryProperty(spec_version='2.1'), required=True)),
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
        [('TLSH', '6FF02BEF718027B0160B4391212923ED7F1A463D563B1549B86CF62973B197AD2731F8')],
    ],
)
def test_hashes_property_valid(value):
    hash_prop = HashesProperty()
    assert hash_prop.clean(value)


@pytest.mark.parametrize(
    "value", [
        {"MD5": "a"},
        {"SHA-256": "2dfb1bcc980200c6706feee399d41b3f"},
        {"TLSH": "6FF02BEF718027B0160B4391212923ED7F1A463D563B1549B86CF62973B197AD2731F"},
    ],
)
def test_hashes_property_invalid(value):
    hash_prop = HashesProperty()

    with pytest.raises(ValueError):
        hash_prop.clean(value)


def test_embedded_property():
    emb_prop = EmbeddedObjectProperty(type=stix2.v21.EmailMIMEComponent)
    mime = stix2.v21.EmailMIMEComponent(
        content_type="text/plain; charset=utf-8",
        content_disposition="inline",
        body="Cats are funny!",
    )
    assert emb_prop.clean(mime)

    with pytest.raises(ValueError):
        emb_prop.clean("string")


def test_extension_property_valid():
    ext_prop = ExtensionsProperty(spec_version='2.1')
    assert ext_prop({
        'windows-pebinary-ext': {
            'pe_type': 'exe',
        },
    })


def test_extension_property_invalid1():
    ext_prop = ExtensionsProperty(spec_version='2.1')
    with pytest.raises(ValueError):
        ext_prop.clean(1)


def test_extension_property_invalid2():
    ext_prop = ExtensionsProperty(spec_version='2.1')
    with pytest.raises(CustomContentError):
        ext_prop.clean(
            {
                'foobar-ext': {
                    'pe_type': 'exe',
                },
            },
        )


def test_extension_at_least_one_property_constraint():
    with pytest.raises(AtLeastOnePropertyError):
        stix2.v21.TCPExt()


def test_marking_property_error():
    mark_prop = MarkingProperty()

    with pytest.raises(ValueError) as excinfo:
        mark_prop.clean('my-marking')

    assert str(excinfo.value) == "must be a Statement, TLP Marking or a registered marking."
