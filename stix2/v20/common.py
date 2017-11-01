"""STIX 2 Common Data Types and Properties."""

from collections import OrderedDict

from ..base import _STIXBase
from ..markings import _MarkingsMixin
from ..properties import (HashesProperty, IDProperty, ListProperty, Property,
                          ReferenceProperty, SelectorProperty, StringProperty,
                          TimestampProperty, TypeProperty)
from ..utils import NOW, get_dict


class ExternalReference(_STIXBase):
    _properties = OrderedDict()
    _properties.update([
        ('source_name', StringProperty(required=True)),
        ('description', StringProperty()),
        ('url', StringProperty()),
        ('hashes', HashesProperty()),
        ('external_id', StringProperty()),
    ])

    def _check_object_constraints(self):
        super(ExternalReference, self)._check_object_constraints()
        self._check_at_least_one_property(["description", "external_id", "url"])


class KillChainPhase(_STIXBase):
    _properties = OrderedDict()
    _properties.update([
        ('kill_chain_name', StringProperty(required=True)),
        ('phase_name', StringProperty(required=True)),
    ])


class GranularMarking(_STIXBase):
    _properties = OrderedDict()
    _properties.update([
        ('marking_ref', ReferenceProperty(required=True, type="marking-definition")),
        ('selectors', ListProperty(SelectorProperty, required=True)),
    ])


class TLPMarking(_STIXBase):
    # TODO: don't allow the creation of any other TLPMarkings than the ones below
    _type = 'tlp'
    _properties = OrderedDict()
    _properties.update([
        ('tlp', Property(required=True))
    ])


class StatementMarking(_STIXBase):
    _type = 'statement'
    _properties = OrderedDict()
    _properties.update([
        ('statement', StringProperty(required=True))
    ])

    def __init__(self, statement=None, **kwargs):
        # Allow statement as positional args.
        if statement and not kwargs.get('statement'):
            kwargs['statement'] = statement

        super(StatementMarking, self).__init__(**kwargs)


class MarkingProperty(Property):
    """Represent the marking objects in the ``definition`` property of
    marking-definition objects.
    """

    def clean(self, value):
        if type(value) in OBJ_MAP_MARKING.values():
            return value
        else:
            raise ValueError("must be a Statement, TLP Marking or a registered marking.")


class MarkingDefinition(_STIXBase, _MarkingsMixin):
    _type = 'marking-definition'
    _properties = OrderedDict()
    _properties.update([
        ('type', TypeProperty(_type)),
        ('id', IDProperty(_type)),
        ('created_by_ref', ReferenceProperty(type="identity")),
        ('created', TimestampProperty(default=lambda: NOW)),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(type="marking-definition"))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('definition_type', StringProperty(required=True)),
        ('definition', MarkingProperty(required=True)),
    ])

    def __init__(self, **kwargs):
        if set(('definition_type', 'definition')).issubset(kwargs.keys()):
            # Create correct marking type object
            try:
                marking_type = OBJ_MAP_MARKING[kwargs['definition_type']]
            except KeyError:
                raise ValueError("definition_type must be a valid marking type")

            if not isinstance(kwargs['definition'], marking_type):
                defn = get_dict(kwargs['definition'])
                kwargs['definition'] = marking_type(**defn)

        super(MarkingDefinition, self).__init__(**kwargs)


OBJ_MAP_MARKING = {
    'tlp': TLPMarking,
    'statement': StatementMarking,
}


def _register_marking(cls):
    """Register a custom STIX Marking Definition type.
    """
    OBJ_MAP_MARKING[cls._type] = cls
    return cls


def CustomMarking(type='x-custom-marking', properties=None):
    """Custom STIX Marking decorator.

    Example:
        >>> @CustomMarking('x-custom-marking', [
        ...     ('property1', StringProperty(required=True)),
        ...     ('property2', IntegerProperty()),
        ... ])
        ... class MyNewMarkingObjectType():
        ...     pass

    """
    def custom_builder(cls):

        class _Custom(cls, _STIXBase):
            _type = type
            _properties = OrderedDict()

            if not properties or not isinstance(properties, list):
                raise ValueError("Must supply a list, containing tuples. For example, [('property1', IntegerProperty())]")

            _properties.update(properties)

            def __init__(self, **kwargs):
                _STIXBase.__init__(self, **kwargs)
                cls.__init__(self, **kwargs)

        _register_marking(_Custom)
        return _Custom

    return custom_builder


TLP_WHITE = MarkingDefinition(
    id="marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    created="2017-01-20T00:00:00.000Z",
    definition_type="tlp",
    definition=TLPMarking(tlp="white")
)

TLP_GREEN = MarkingDefinition(
    id="marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
    created="2017-01-20T00:00:00.000Z",
    definition_type="tlp",
    definition=TLPMarking(tlp="green")
)

TLP_AMBER = MarkingDefinition(
    id="marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    created="2017-01-20T00:00:00.000Z",
    definition_type="tlp",
    definition=TLPMarking(tlp="amber")
)

TLP_RED = MarkingDefinition(
    id="marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
    created="2017-01-20T00:00:00.000Z",
    definition_type="tlp",
    definition=TLPMarking(tlp="red")
)
