from collections import OrderedDict
import datetime
import uuid

import pytest

import stix2.base
import stix2.canonicalization.Canonicalize
import stix2.exceptions
from stix2.properties import (
    BooleanProperty, DictionaryProperty, EmbeddedObjectProperty,
    ExtensionsProperty, FloatProperty, HashesProperty, IDProperty,
    IntegerProperty, ListProperty, StringProperty, TimestampProperty,
    TypeProperty,
)
import stix2.v21
from stix2.v21.vocab import HASHING_ALGORITHM

SCO_DET_ID_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")


def _uuid_from_id(id_):
    dd_idx = id_.index("--")
    uuid_str = id_[dd_idx+2:]
    uuid_ = uuid.UUID(uuid_str)

    return uuid_


def _make_uuid5(name):
    """
    Make a STIX 2.1+ compliant UUIDv5 from a "name".
    """
    uuid_ = uuid.uuid5(SCO_DET_ID_NAMESPACE, name)

    return uuid_


def test_no_contrib_props_defined():

    class SomeSCO(stix2.v21._Observable):
        _type = "some-sco"
        _properties = OrderedDict((
            ('type', TypeProperty(_type, spec_version='2.1')),
            ('id', IDProperty(_type, spec_version='2.1')),
            ('extensions', ExtensionsProperty(spec_version='2.1')),
        ))
        _id_contributing_properties = []

    sco = SomeSCO()
    uuid_ = _uuid_from_id(sco["id"])

    assert uuid_.variant == uuid.RFC_4122
    assert uuid_.version == 4


def test_json_compatible_prop_values():
    class SomeSCO(stix2.v21._Observable):
        _type = "some-sco"
        _properties = OrderedDict((
            ('type', TypeProperty(_type, spec_version='2.1')),
            ('id', IDProperty(_type, spec_version='2.1')),
            ('extensions', ExtensionsProperty(spec_version='2.1')),
            ('string', StringProperty()),
            ('int', IntegerProperty()),
            ('float', FloatProperty()),
            ('bool', BooleanProperty()),
            ('list', ListProperty(IntegerProperty())),
            ('dict', DictionaryProperty(spec_version="2.1")),
        ))
        _id_contributing_properties = [
            'string', 'int', 'float', 'bool', 'list', 'dict',
        ]

    obj = {
        "string": "abc",
        "int": 1,
        "float": 1.5,
        "bool": True,
        "list": [1, 2, 3],
        "dict": {"a": 1, "b": [2], "c": "three"},
    }

    sco = SomeSCO(**obj)

    can_json = stix2.canonicalization.Canonicalize.canonicalize(obj, utf8=False)
    expected_uuid5 = _make_uuid5(can_json)
    actual_uuid5 = _uuid_from_id(sco["id"])

    assert actual_uuid5 == expected_uuid5


def test_json_incompatible_timestamp_value():
    class SomeSCO(stix2.v21._Observable):
        _type = "some-sco"
        _properties = OrderedDict((
            ('type', TypeProperty(_type, spec_version='2.1')),
            ('id', IDProperty(_type, spec_version='2.1')),
            ('extensions', ExtensionsProperty(spec_version='2.1')),
            ('timestamp', TimestampProperty()),
        ))
        _id_contributing_properties = ['timestamp']

    ts = datetime.datetime(1987, 1, 2, 3, 4, 5, 678900)

    sco = SomeSCO(timestamp=ts)

    obj = {
        "timestamp": "1987-01-02T03:04:05.6789Z",
    }

    can_json = stix2.canonicalization.Canonicalize.canonicalize(obj, utf8=False)
    expected_uuid5 = _make_uuid5(can_json)
    actual_uuid5 = _uuid_from_id(sco["id"])

    assert actual_uuid5 == expected_uuid5


def test_embedded_object():
    class SubObj(stix2.base._STIXBase):
        _type = "sub-object"
        _properties = OrderedDict((
            ('value', StringProperty()),
        ))

    class SomeSCO(stix2.v21._Observable):
        _type = "some-sco"
        _properties = OrderedDict((
            ('type', TypeProperty(_type, spec_version='2.1')),
            ('id', IDProperty(_type, spec_version='2.1')),
            ('extensions', ExtensionsProperty(spec_version='2.1')),
            ('sub_obj', EmbeddedObjectProperty(type=SubObj)),
        ))
        _id_contributing_properties = ['sub_obj']

    sub_obj = SubObj(value="foo")
    sco = SomeSCO(sub_obj=sub_obj)

    obj = {
        "sub_obj": {
            "value": "foo",
        },
    }

    can_json = stix2.canonicalization.Canonicalize.canonicalize(obj, utf8=False)
    expected_uuid5 = _make_uuid5(can_json)
    actual_uuid5 = _uuid_from_id(sco["id"])

    assert actual_uuid5 == expected_uuid5


def test_empty_hash():
    class SomeSCO(stix2.v21._Observable):
        _type = "some-sco"
        _properties = OrderedDict((
            ('type', TypeProperty(_type, spec_version='2.1')),
            ('id', IDProperty(_type, spec_version='2.1')),
            ('extensions', ExtensionsProperty(spec_version='2.1')),
            ('hashes', HashesProperty(HASHING_ALGORITHM)),
        ))
        _id_contributing_properties = ['hashes']

    with pytest.raises(stix2.exceptions.InvalidValueError):
        SomeSCO(hashes={})


@pytest.mark.parametrize(
    "json_escaped, expected_unescaped", [
        ("", ""),
        ("a", "a"),
        (r"\n", "\n"),
        (r"\n\r\b\t\\\/\"", "\n\r\b\t\\/\""),
        (r"\\n", r"\n"),
        (r"\\\n", "\\\n"),
    ],
)
def test_json_unescaping(json_escaped, expected_unescaped):
    actual_unescaped = stix2.base._un_json_escape(json_escaped)
    assert actual_unescaped == expected_unescaped


def test_json_unescaping_bad_escape():
    with pytest.raises(ValueError):
        stix2.base._un_json_escape(r"\x")


def test_deterministic_id_same_extra_prop_vals():
    email_addr_1 = stix2.v21.EmailAddress(
        value="john@example.com",
        display_name="Johnny Doe",
    )

    email_addr_2 = stix2.v21.EmailAddress(
        value="john@example.com",
        display_name="Johnny Doe",
    )

    assert email_addr_1.id == email_addr_2.id

    uuid_obj_1 = uuid.UUID(email_addr_1.id[-36:])
    assert uuid_obj_1.variant == uuid.RFC_4122
    assert uuid_obj_1.version == 5

    uuid_obj_2 = uuid.UUID(email_addr_2.id[-36:])
    assert uuid_obj_2.variant == uuid.RFC_4122
    assert uuid_obj_2.version == 5


def test_deterministic_id_diff_extra_prop_vals():
    email_addr_1 = stix2.v21.EmailAddress(
        value="john@example.com",
        display_name="Johnny Doe",
    )

    email_addr_2 = stix2.v21.EmailAddress(
        value="john@example.com",
        display_name="Janey Doe",
    )

    assert email_addr_1.id == email_addr_2.id

    uuid_obj_1 = uuid.UUID(email_addr_1.id[-36:])
    assert uuid_obj_1.variant == uuid.RFC_4122
    assert uuid_obj_1.version == 5

    uuid_obj_2 = uuid.UUID(email_addr_2.id[-36:])
    assert uuid_obj_2.variant == uuid.RFC_4122
    assert uuid_obj_2.version == 5


def test_deterministic_id_diff_contributing_prop_vals():
    email_addr_1 = stix2.v21.EmailAddress(
        value="john@example.com",
        display_name="Johnny Doe",
    )

    email_addr_2 = stix2.v21.EmailAddress(
        value="jane@example.com",
        display_name="Janey Doe",
    )

    assert email_addr_1.id != email_addr_2.id

    uuid_obj_1 = uuid.UUID(email_addr_1.id[-36:])
    assert uuid_obj_1.variant == uuid.RFC_4122
    assert uuid_obj_1.version == 5

    uuid_obj_2 = uuid.UUID(email_addr_2.id[-36:])
    assert uuid_obj_2.variant == uuid.RFC_4122
    assert uuid_obj_2.version == 5


def test_deterministic_id_no_contributing_props():
    email_msg_1 = stix2.v21.EmailMessage(
        is_multipart=False,
    )

    email_msg_2 = stix2.v21.EmailMessage(
        is_multipart=False,
    )

    assert email_msg_1.id != email_msg_2.id

    uuid_obj_1 = uuid.UUID(email_msg_1.id[-36:])
    assert uuid_obj_1.variant == uuid.RFC_4122
    assert uuid_obj_1.version == 4

    uuid_obj_2 = uuid.UUID(email_msg_2.id[-36:])
    assert uuid_obj_2.variant == uuid.RFC_4122
    assert uuid_obj_2.version == 4


def test_id_gen_recursive_dict_conversion_1():
    file_observable = stix2.v21.File(
        name="example.exe",
        size=68 * 1000,
        magic_number_hex="50000000",
        hashes={
            "SHA-256": "841a8921140aba50671ebb0770fecc4ee308c4952cfeff8de154ab14eeef4649",
        },
        extensions={
            "windows-pebinary-ext": stix2.v21.WindowsPEBinaryExt(
                pe_type="exe",
                machine_hex="014c",
                sections=[
                    stix2.v21.WindowsPESection(
                        name=".data",
                        size=4096,
                        entropy=7.980693,
                        hashes={"SHA-256": "6e3b6f3978e5cd96ba7abee35c24e867b7e64072e2ecb22d0ee7a6e6af6894d0"},
                    ),
                ],
            ),
        },
    )

    assert file_observable.id == "file--ced31cd4-bdcb-537d-aefa-92d291bfc11d"


def test_id_gen_recursive_dict_conversion_2():
    wrko = stix2.v21.WindowsRegistryKey(
        values=[
            stix2.v21.WindowsRegistryValueType(
                name="Foo",
                data="qwerty",
            ),
            stix2.v21.WindowsRegistryValueType(
                name="Bar",
                data="42",
            ),
        ],
    )

    assert wrko.id == "windows-registry-key--36594eba-bcc7-5014-9835-0e154264e588"
