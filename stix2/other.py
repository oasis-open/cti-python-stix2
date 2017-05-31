"""STIX 2.0 Objects that are neither SDOs nor SROs"""

from .base import _STIXBase
from .properties import (IDProperty, ListProperty, Property, ReferenceProperty,
                         SelectorProperty, StringProperty, TimestampProperty,
                         TypeProperty)
from .utils import NOW, get_dict


class ExternalReference(_STIXBase):
    _properties = {
        'source_name': StringProperty(required=True),
        'description': StringProperty(),
        'url': StringProperty(),
        'external_id': StringProperty(),
    }

    def _check_object_constraints(self):
        super(ExternalReference, self)._check_object_constraints()
        self._check_at_least_one_property(["description", "external_id", "url"])


class KillChainPhase(_STIXBase):
    _properties = {
        'kill_chain_name': StringProperty(required=True),
        'phase_name': StringProperty(required=True),
    }


class GranularMarking(_STIXBase):
    _properties = {
        'marking_ref': ReferenceProperty(required=True, type="marking-definition"),
        'selectors': ListProperty(SelectorProperty, required=True),
    }


class TLPMarking(_STIXBase):
    # TODO: don't allow the creation of any other TLPMarkings than the ones below
    _properties = {
        'tlp': Property(required=True)
    }


class StatementMarking(_STIXBase):
    _properties = {
        'statement': StringProperty(required=True)
    }

    def __init__(self, statement=None, **kwargs):
        # Allow statement as positional args.
        if statement and not kwargs.get('statement'):
            kwargs['statement'] = statement

        super(StatementMarking, self).__init__(**kwargs)


class MarkingProperty(Property):
    """Represent the marking objects in the `definition` property of
    marking-definition objects.
    """

    def clean(self, value):
        if type(value) in [TLPMarking, StatementMarking]:
            return value
        else:
            raise ValueError("must be a Statement or TLP Marking.")


class MarkingDefinition(_STIXBase):
    _type = 'marking-definition'
    _properties = {
        'created': TimestampProperty(default=lambda: NOW, required=True),
        'external_references': ListProperty(ExternalReference),
        'created_by_ref': ReferenceProperty(type="identity"),
        'object_marking_refs': ListProperty(ReferenceProperty(type="marking-definition")),
        'granular_markings': ListProperty(GranularMarking),
        'type': TypeProperty(_type),
        'id': IDProperty(_type),
        'definition_type': StringProperty(required=True),
        'definition': MarkingProperty(required=True),
    }
    marking_map = {
        'tlp': TLPMarking,
        'statement': StatementMarking,
    }

    def __init__(self, **kwargs):
        if set(('definition_type', 'definition')).issubset(kwargs.keys()):
            # Create correct marking type object
            try:
                marking_type = self.marking_map[kwargs['definition_type']]
            except KeyError:
                raise ValueError("definition_type must be a valid marking type")

            if not isinstance(kwargs['definition'], marking_type):
                defn = get_dict(kwargs['definition'])
                kwargs['definition'] = marking_type(**defn)

        super(MarkingDefinition, self).__init__(**kwargs)


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
