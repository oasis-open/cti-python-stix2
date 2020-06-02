from collections import OrderedDict
import datetime
import uuid

import six

import stix2.base
import stix2.canonicalization.Canonicalize
from stix2.properties import (
    BooleanProperty, DictionaryProperty, EmbeddedObjectProperty,
    ExtensionsProperty, FloatProperty, IDProperty, IntegerProperty,
    ListProperty, StringProperty, TimestampProperty, TypeProperty,
)
import stix2.v21.base

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
    if six.PY3:
        uuid_ = uuid.uuid5(SCO_DET_ID_NAMESPACE, name)
    else:
        uuid_ = uuid.uuid5(
            SCO_DET_ID_NAMESPACE, name.encode("utf-8"),
        )

    return uuid_


def test_no_contrib_props_defined():

    class SomeSCO(stix2.v21.base._Observable):
        _type = "some-sco"
        _properties = OrderedDict((
            ('type', TypeProperty(_type, spec_version='2.1')),
            ('id', IDProperty(_type, spec_version='2.1')),
            (
                'extensions', ExtensionsProperty(
                    spec_version='2.1', enclosing_type=_type,
                ),
            ),
        ))
        _id_contributing_properties = []

    sco = SomeSCO()
    uuid_ = _uuid_from_id(sco["id"])

    assert uuid_.variant == uuid.RFC_4122
    assert uuid_.version == 4


def test_no_contrib_props_given():

    class SomeSCO(stix2.v21.base._Observable):
        _type = "some-sco"
        _properties = OrderedDict((
            ('type', TypeProperty(_type, spec_version='2.1')),
            ('id', IDProperty(_type, spec_version='2.1')),
            (
                'extensions', ExtensionsProperty(
                    spec_version='2.1', enclosing_type=_type,
                ),
            ),
            ('value', StringProperty()),
        ))
        _id_contributing_properties = ['value']

    sco = SomeSCO()
    uuid_ = _uuid_from_id(sco["id"])

    assert uuid_.variant == uuid.RFC_4122
    assert uuid_.version == 4


def test_json_compatible_prop_values():
    class SomeSCO(stix2.v21.base._Observable):
        _type = "some-sco"
        _properties = OrderedDict((
            ('type', TypeProperty(_type, spec_version='2.1')),
            ('id', IDProperty(_type, spec_version='2.1')),
            (
                'extensions', ExtensionsProperty(
                    spec_version='2.1', enclosing_type=_type,
                ),
            ),
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
    class SomeSCO(stix2.v21.base._Observable):
        _type = "some-sco"
        _properties = OrderedDict((
            ('type', TypeProperty(_type, spec_version='2.1')),
            ('id', IDProperty(_type, spec_version='2.1')),
            (
                'extensions', ExtensionsProperty(
                    spec_version='2.1', enclosing_type=_type,
                ),
            ),
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

    class SomeSCO(stix2.v21.base._Observable):
        _type = "some-sco"
        _properties = OrderedDict((
            ('type', TypeProperty(_type, spec_version='2.1')),
            ('id', IDProperty(_type, spec_version='2.1')),
            (
                'extensions', ExtensionsProperty(
                    spec_version='2.1', enclosing_type=_type,
                ),
            ),
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
