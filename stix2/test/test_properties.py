import pytest

from stix2.properties import (Property, BooleanProperty, ListProperty,
                              StringProperty, TypeProperty, IDProperty,
                              ReferenceProperty, TimestampProperty)
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


def test_default_field():
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
    assert str(excinfo.value) == "must have a valid version 4 UUID after the prefix."

    assert idprop.clean(idprop.default())


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
