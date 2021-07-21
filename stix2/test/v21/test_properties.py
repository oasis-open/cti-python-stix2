import pytest

import stix2
from stix2.exceptions import (
    AtLeastOnePropertyError, CustomContentError, DictionaryKeyError,
    ExtraPropertiesError, ParseError,
)
from stix2.properties import (
    DictionaryProperty, EmbeddedObjectProperty, ExtensionsProperty,
    HashesProperty, IDProperty, ListProperty, ObservableProperty,
    ReferenceProperty, STIXObjectProperty, StringProperty,
)
from stix2.v21.common import MarkingProperty

from . import constants


def test_dictionary_property():
    p = DictionaryProperty(StringProperty)

    assert p.clean({'spec_version': '2.1'})
    with pytest.raises(ValueError):
        p.clean({})


ID_PROP = IDProperty('my-type', spec_version="2.1")
MY_ID = 'my-type--232c9d3f-49fc-4440-bb01-607f638778e7'


@pytest.mark.parametrize(
    "value", [
        MY_ID,
        'my-type--00000000-0000-4000-8000-000000000000',
    ],
)
def test_id_property_valid(value):
    assert ID_PROP.clean(value) == (value, False)


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
    assert IDProperty(type=type, spec_version="2.1").clean(value) == (value, False)


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
    assert ID_PROP.clean(default) == (default, False)


def test_reference_property_whitelist_standard_type():
    ref_prop = ReferenceProperty(valid_types="identity", spec_version="2.1")
    result = ref_prop.clean(
        "identity--8a8e8758-f92c-4058-ba38-f061cd42a0cf", False,
    )
    assert result == ("identity--8a8e8758-f92c-4058-ba38-f061cd42a0cf", False)

    with pytest.raises(ValueError):
        ref_prop.clean("foo--8a8e8758-f92c-4058-ba38-f061cd42a0cf", True)

    with pytest.raises(ValueError):
        ref_prop.clean("foo--8a8e8758-f92c-4058-ba38-f061cd42a0cf", False)


def test_reference_property_whitelist_custom_type():
    ref_prop = ReferenceProperty(valid_types="my-type", spec_version="2.1")

    with pytest.raises(ValueError):
        ref_prop.clean("not-my-type--8a8e8758-f92c-4058-ba38-f061cd42a0cf", False)

    with pytest.raises(ValueError):
        ref_prop.clean("not-my-type--8a8e8758-f92c-4058-ba38-f061cd42a0cf", True)

    with pytest.raises(CustomContentError):
        # This is the whitelisted type, but it's still custom, and
        # customization is disallowed here.
        ref_prop.clean("my-type--8a8e8758-f92c-4058-ba38-f061cd42a0cf", False)

    result = ref_prop.clean("my-type--8a8e8758-f92c-4058-ba38-f061cd42a0cf", True)
    assert result == ("my-type--8a8e8758-f92c-4058-ba38-f061cd42a0cf", True)


def test_reference_property_whitelist_generic_type():
    ref_prop = ReferenceProperty(
        valid_types=["SCO", "SRO"], spec_version="2.1",
    )

    result = ref_prop.clean("file--8a8e8758-f92c-4058-ba38-f061cd42a0cf", False)
    assert result == ("file--8a8e8758-f92c-4058-ba38-f061cd42a0cf", False)

    result = ref_prop.clean("file--8a8e8758-f92c-4058-ba38-f061cd42a0cf", True)
    assert result == ("file--8a8e8758-f92c-4058-ba38-f061cd42a0cf", False)

    result = ref_prop.clean(
        "sighting--8a8e8758-f92c-4058-ba38-f061cd42a0cf", False,
    )
    assert result == ("sighting--8a8e8758-f92c-4058-ba38-f061cd42a0cf", False)

    result = ref_prop.clean(
        "sighting--8a8e8758-f92c-4058-ba38-f061cd42a0cf", True,
    )
    assert result == ("sighting--8a8e8758-f92c-4058-ba38-f061cd42a0cf", False)

    # The prop assumes some-type is a custom type of one of the generic
    # type categories.
    result = ref_prop.clean(
        "some-type--8a8e8758-f92c-4058-ba38-f061cd42a0cf", True,
    )
    assert result == ("some-type--8a8e8758-f92c-4058-ba38-f061cd42a0cf", True)

    with pytest.raises(ValueError):
        ref_prop.clean("some-type--8a8e8758-f92c-4058-ba38-f061cd42a0cf", False)

    with pytest.raises(ValueError):
        ref_prop.clean("identity--8a8e8758-f92c-4058-ba38-f061cd42a0cf", False)

    with pytest.raises(ValueError):
        ref_prop.clean("identity--8a8e8758-f92c-4058-ba38-f061cd42a0cf", True)


def test_reference_property_blacklist_standard_type():
    ref_prop = ReferenceProperty(invalid_types="identity", spec_version="2.1")
    result = ref_prop.clean(
        "location--8a8e8758-f92c-4058-ba38-f061cd42a0cf", False,
    )
    assert result == ("location--8a8e8758-f92c-4058-ba38-f061cd42a0cf", False)

    result = ref_prop.clean(
        "location--8a8e8758-f92c-4058-ba38-f061cd42a0cf", True,
    )
    assert result == ("location--8a8e8758-f92c-4058-ba38-f061cd42a0cf", False)

    with pytest.raises(CustomContentError):
        ref_prop.clean(
            "some-type--8a8e8758-f92c-4058-ba38-f061cd42a0cf", False,
        )

    result = ref_prop.clean(
        "some-type--8a8e8758-f92c-4058-ba38-f061cd42a0cf", True,
    )
    assert result == ("some-type--8a8e8758-f92c-4058-ba38-f061cd42a0cf", True)

    with pytest.raises(ValueError):
        ref_prop.clean(
            "identity--8a8e8758-f92c-4058-ba38-f061cd42a0cf", False,
        )

    with pytest.raises(ValueError):
        ref_prop.clean(
            "identity--8a8e8758-f92c-4058-ba38-f061cd42a0cf", True,
        )


def test_reference_property_blacklist_custom_type():
    ref_prop = ReferenceProperty(invalid_types="my-type", spec_version="2.1")

    result = ref_prop.clean("file--8a8e8758-f92c-4058-ba38-f061cd42a0cf", False)
    assert result == ("file--8a8e8758-f92c-4058-ba38-f061cd42a0cf", False)

    with pytest.raises(ValueError):
        ref_prop.clean("my-type--8a8e8758-f92c-4058-ba38-f061cd42a0cf", False)

    with pytest.raises(ValueError):
        ref_prop.clean("my-type--8a8e8758-f92c-4058-ba38-f061cd42a0cf", True)

    with pytest.raises(CustomContentError):
        # This is not the blacklisted type, but it's still custom, and
        # customization is disallowed here.
        ref_prop.clean("not-my-type--8a8e8758-f92c-4058-ba38-f061cd42a0cf", False)

    result = ref_prop.clean("not-my-type--8a8e8758-f92c-4058-ba38-f061cd42a0cf", True)
    assert result == ("not-my-type--8a8e8758-f92c-4058-ba38-f061cd42a0cf", True)


def test_reference_property_blacklist_generic_type():
    ref_prop = ReferenceProperty(
        invalid_types=["SDO", "SRO"], spec_version="2.1",
    )

    result = ref_prop.clean(
        "file--8a8e8758-f92c-4058-ba38-f061cd42a0cf", False,
    )
    assert result == ("file--8a8e8758-f92c-4058-ba38-f061cd42a0cf", False)

    result = ref_prop.clean(
        "file--8a8e8758-f92c-4058-ba38-f061cd42a0cf", True,
    )
    assert result == ("file--8a8e8758-f92c-4058-ba38-f061cd42a0cf", False)

    with pytest.raises(CustomContentError):
        ref_prop.clean(
            "some-type--8a8e8758-f92c-4058-ba38-f061cd42a0cf", False,
        )

    result = ref_prop.clean(
        "some-type--8a8e8758-f92c-4058-ba38-f061cd42a0cf", True,
    )
    assert result == ("some-type--8a8e8758-f92c-4058-ba38-f061cd42a0cf", True)

    with pytest.raises(ValueError):
        ref_prop.clean(
            "identity--8a8e8758-f92c-4058-ba38-f061cd42a0cf", False,
        )

    with pytest.raises(ValueError):
        ref_prop.clean(
            "identity--8a8e8758-f92c-4058-ba38-f061cd42a0cf", True,
        )

    with pytest.raises(ValueError):
        ref_prop.clean(
            "relationship--8a8e8758-f92c-4058-ba38-f061cd42a0cf", False,
        )

    with pytest.raises(ValueError):
        ref_prop.clean(
            "relationship--8a8e8758-f92c-4058-ba38-f061cd42a0cf", True,
        )


def test_reference_property_whitelist_hybrid_type():
    p = ReferenceProperty(valid_types=["a", "SCO"], spec_version="2.1")

    result = p.clean("file--8a8e8758-f92c-4058-ba38-f061cd42a0cf", False)
    assert result == ("file--8a8e8758-f92c-4058-ba38-f061cd42a0cf", False)

    result = p.clean("file--8a8e8758-f92c-4058-ba38-f061cd42a0cf", True)
    assert result == ("file--8a8e8758-f92c-4058-ba38-f061cd42a0cf", False)

    with pytest.raises(CustomContentError):
        # although whitelisted, "a" is a custom type
        p.clean("a--8a8e8758-f92c-4058-ba38-f061cd42a0cf", False)

    result = p.clean("a--8a8e8758-f92c-4058-ba38-f061cd42a0cf", True)
    assert result == ("a--8a8e8758-f92c-4058-ba38-f061cd42a0cf", True)

    with pytest.raises(ValueError):
        p.clean("b--8a8e8758-f92c-4058-ba38-f061cd42a0cf", False)

    # should just assume "b" is a custom SCO type.
    result = p.clean("b--8a8e8758-f92c-4058-ba38-f061cd42a0cf", True)
    assert result == ("b--8a8e8758-f92c-4058-ba38-f061cd42a0cf", True)


def test_reference_property_blacklist_hybrid_type():
    p = ReferenceProperty(invalid_types=["a", "SCO"], spec_version="2.1")

    with pytest.raises(ValueError):
        p.clean("file--8a8e8758-f92c-4058-ba38-f061cd42a0cf", False)

    with pytest.raises(ValueError):
        p.clean("file--8a8e8758-f92c-4058-ba38-f061cd42a0cf", True)

    with pytest.raises(ValueError):
        p.clean("a--8a8e8758-f92c-4058-ba38-f061cd42a0cf", False)

    with pytest.raises(ValueError):
        p.clean("a--8a8e8758-f92c-4058-ba38-f061cd42a0cf", True)

    with pytest.raises(CustomContentError):
        p.clean("b--8a8e8758-f92c-4058-ba38-f061cd42a0cf", False)

    # should just assume "b" is a custom type which is not an SCO
    result = p.clean("b--8a8e8758-f92c-4058-ba38-f061cd42a0cf", True)
    assert result == ("b--8a8e8758-f92c-4058-ba38-f061cd42a0cf", True)


def test_reference_property_impossible_constraint():
    with pytest.raises(ValueError):
        ReferenceProperty(valid_types=[], spec_version="2.1")


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
    "key", [
        "a",
        "a"*250,
        "a-1_b",
    ],
)
def test_hash_property_valid_key(key):
    p = HashesProperty(["foo"], spec_version="2.1")
    result = p.clean({key: "bar"}, True)
    assert result == ({key: "bar"}, True)


@pytest.mark.parametrize(
    "key", [
        "",
        "a"*251,
        "funny%chars?",
    ],
)
def test_hash_property_invalid_key(key):
    p = HashesProperty(["foo"], spec_version="2.1")
    with pytest.raises(DictionaryKeyError):
        p.clean({key: "foo"}, True)


def test_embedded_property():
    emb_prop = EmbeddedObjectProperty(type=stix2.v21.EmailMIMEComponent)
    mime = stix2.v21.EmailMIMEComponent(
        content_type="text/plain; charset=utf-8",
        content_disposition="inline",
        body="Cats are funny!",
    )
    result = emb_prop.clean(mime, False)
    assert result == (mime, False)

    result = emb_prop.clean(mime, True)
    assert result == (mime, False)

    with pytest.raises(ValueError):
        emb_prop.clean("string", False)


def test_embedded_property_dict():
    emb_prop = EmbeddedObjectProperty(type=stix2.v21.EmailMIMEComponent)
    mime = {
        "content_type": "text/plain; charset=utf-8",
        "content_disposition": "inline",
        "body": "Cats are funny!",
    }

    result = emb_prop.clean(mime, False)
    assert isinstance(result[0], stix2.v21.EmailMIMEComponent)
    assert result[0]["body"] == "Cats are funny!"
    assert not result[1]

    result = emb_prop.clean(mime, True)
    assert isinstance(result[0], stix2.v21.EmailMIMEComponent)
    assert result[0]["body"] == "Cats are funny!"
    assert not result[1]


def test_embedded_property_custom():
    emb_prop = EmbeddedObjectProperty(type=stix2.v21.EmailMIMEComponent)
    mime = stix2.v21.EmailMIMEComponent(
        content_type="text/plain; charset=utf-8",
        content_disposition="inline",
        body="Cats are funny!",
        foo=123,
        allow_custom=True,
    )

    with pytest.raises(CustomContentError):
        emb_prop.clean(mime, False)

    result = emb_prop.clean(mime, True)
    assert result == (mime, True)


def test_embedded_property_dict_custom():
    emb_prop = EmbeddedObjectProperty(type=stix2.v21.EmailMIMEComponent)
    mime = {
        "content_type": "text/plain; charset=utf-8",
        "content_disposition": "inline",
        "body": "Cats are funny!",
        "foo": 123,
    }

    with pytest.raises(ExtraPropertiesError):
        emb_prop.clean(mime, False)

    result = emb_prop.clean(mime, True)
    assert isinstance(result[0], stix2.v21.EmailMIMEComponent)
    assert result[0]["body"] == "Cats are funny!"
    assert result[1]


def test_extension_property_valid():
    ext_prop = ExtensionsProperty(spec_version='2.1')
    result = ext_prop.clean(
        {
            'windows-pebinary-ext': {
                'pe_type': 'exe',
            },
        }, False,
    )

    assert isinstance(
        result[0]["windows-pebinary-ext"], stix2.v21.WindowsPEBinaryExt,
    )
    assert not result[1]

    result = ext_prop.clean(
        {
            'windows-pebinary-ext': {
                'pe_type': 'exe',
            },
        }, True,
    )

    assert isinstance(
        result[0]["windows-pebinary-ext"], stix2.v21.WindowsPEBinaryExt,
    )
    assert not result[1]


def test_extension_property_invalid1():
    ext_prop = ExtensionsProperty(spec_version='2.1')
    with pytest.raises(ValueError):
        ext_prop.clean(1, False)


def test_extension_property_invalid2():
    ext_prop = ExtensionsProperty(spec_version='2.1')
    with pytest.raises(CustomContentError):
        ext_prop.clean(
            {
                'foobar-ext': {
                    'pe_type': 'exe',
                },
            },
            False,
        )

    result = ext_prop.clean(
        {
            'foobar-ext': {
                'pe_type': 'exe',
            },
        }, True,
    )
    assert result == ({"foobar-ext": {"pe_type": "exe"}}, True)


def test_extension_property_invalid3():
    ext_prop = ExtensionsProperty(spec_version="2.1")
    with pytest.raises(ExtraPropertiesError):
        ext_prop.clean(
            {
                'windows-pebinary-ext': {
                    'pe_type': 'exe',
                    'abc': 123,
                },
            },
            False,
        )

    result = ext_prop.clean(
        {
            'windows-pebinary-ext': {
                'pe_type': 'exe',
                'abc': 123,
            },
        }, True,
    )

    assert isinstance(
        result[0]["windows-pebinary-ext"], stix2.v21.WindowsPEBinaryExt,
    )
    assert result[0]["windows-pebinary-ext"]["abc"] == 123
    assert result[1]


def test_extension_at_least_one_property_constraint():
    with pytest.raises(AtLeastOnePropertyError):
        stix2.v21.TCPExt()


def test_marking_property_error():
    mark_prop = MarkingProperty()

    with pytest.raises(ValueError) as excinfo:
        mark_prop.clean('my-marking')

    assert str(excinfo.value) == "must be a Statement, TLP Marking or a registered marking."


def test_observable_property_obj():
    prop = ObservableProperty(spec_version="2.1")

    obs = stix2.v21.File(name="data.dat")
    obs_dict = {
        "0": obs,
    }

    result = prop.clean(obs_dict, False)
    assert result[0]["0"] == obs
    assert not result[1]

    result = prop.clean(obs_dict, True)
    assert result[0]["0"] == obs
    assert not result[1]


def test_observable_property_dict():
    prop = ObservableProperty(spec_version="2.1")

    obs_dict = {
        "0": {
            "type": "file",
            "name": "data.dat",
        },
    }

    result = prop.clean(obs_dict, False)
    assert isinstance(result[0]["0"], stix2.v21.File)
    assert result[0]["0"]["name"] == "data.dat"
    assert not result[1]

    result = prop.clean(obs_dict, True)
    assert isinstance(result[0]["0"], stix2.v21.File)
    assert result[0]["0"]["name"] == "data.dat"
    assert not result[1]


def test_observable_property_obj_custom():
    prop = ObservableProperty(spec_version="2.1")

    obs = stix2.v21.File(name="data.dat", foo=True, allow_custom=True)
    obs_dict = {
        "0": obs,
    }

    with pytest.raises(ExtraPropertiesError):
        prop.clean(obs_dict, False)

    result = prop.clean(obs_dict, True)
    assert result[0]["0"] == obs
    assert result[1]


def test_observable_property_dict_custom():
    prop = ObservableProperty(spec_version="2.1")

    obs_dict = {
        "0": {
            "type": "file",
            "name": "data.dat",
            "foo": True,
        },
    }

    with pytest.raises(ExtraPropertiesError):
        prop.clean(obs_dict, False)

    result = prop.clean(obs_dict, True)
    assert isinstance(result[0]["0"], stix2.v21.File)
    assert result[0]["0"]["foo"]
    assert result[1]


def test_stix_object_property_custom_prop():
    prop = STIXObjectProperty(spec_version="2.1")

    obj_dict = {
        "type": "identity",
        "spec_version": "2.1",
        "name": "alice",
        "identity_class": "supergirl",
        "foo": "bar",
    }

    with pytest.raises(ExtraPropertiesError):
        prop.clean(obj_dict, False)

    result = prop.clean(obj_dict, True)
    assert isinstance(result[0], stix2.v21.Identity)
    assert result[0].has_custom
    assert result[0]["foo"] == "bar"
    assert result[1]


def test_stix_object_property_custom_obj():
    prop = STIXObjectProperty(spec_version="2.1")

    obj_dict = {
        "type": "something",
        "abc": 123,
        "xyz": ["a", 1],
    }

    with pytest.raises(ParseError):
        prop.clean(obj_dict, False)

    result = prop.clean(obj_dict, True)
    assert result[0] == {"type": "something", "abc": 123, "xyz": ["a", 1]}
    assert result[1]
