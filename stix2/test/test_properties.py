import pytest

from stix2.properties import (Property, BooleanProperty, IDProperty,
                              ReferenceProperty, TypeProperty)


def test_property():
    p = Property()

    assert p.required is False


def test_basic_validate():
    class Prop(Property):

        def validate(self, value):
            if value == 42:
                return value
            else:
                raise ValueError("Must be 42")

    p = Prop()

    assert p.validate(42) == 42
    with pytest.raises(ValueError):
        p.validate(41)


def test_default_field():
    class Prop(Property):

        def default(self):
            return 77

    p = Prop()

    assert p.default() == 77


def test_fixed_property():
    p = Property(fixed="2.0")

    assert p.validate("2.0")
    with pytest.raises(ValueError):
        assert p.validate("x") is False
    with pytest.raises(ValueError):
        assert p.validate(2.0) is False

    assert p.default() == "2.0"
    assert p.validate(p.default())


def test_type_property():
    prop = TypeProperty('my-type')

    assert prop.validate('my-type')
    with pytest.raises(ValueError):
        prop.validate('not-my-type')
    assert prop.validate(prop.default())


def test_id_property():
    idprop = IDProperty('my-type')

    assert idprop.validate('my-type--90aaca8a-1110-5d32-956d-ac2f34a1bd8c')
    with pytest.raises(ValueError):
        idprop.validate('not-my-type--90aaca8a-1110-5d32-956d-ac2f34a1bd8c')
    assert idprop.validate(idprop.default())


def test_boolean_property():
    bool_prop = BooleanProperty()

    assert bool_prop.validate(True) is not None
    assert bool_prop.validate(False) is not None
    for invalid in ('true', 'false', "T", "F", 1, 0):
        print(invalid)
        with pytest.raises(ValueError):
            bool_prop.validate(invalid)


def test_reference_property():
    ref_prop = ReferenceProperty()

    assert ref_prop.validate("my-type--3a331bfe-0566-55e1-a4a0-9a2cd355a300")
    with pytest.raises(ValueError):
        ref_prop.validate("foo")
