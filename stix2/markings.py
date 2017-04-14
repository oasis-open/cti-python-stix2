"""STIX 2.0 Marking Objects"""

from .base import _STIXBase
from .properties import IDProperty, TypeProperty, ListProperty, ReferenceProperty, Property, SelectorProperty
from .utils import NOW


class GranularMarking(_STIXBase):
    _properties = {
        'marking_ref': ReferenceProperty(required=True, type="marking-definition"),
        'selectors': ListProperty(SelectorProperty, required=True),
    }


class MarkingDefinition(_STIXBase):
    _type = 'marking-definition'
    _properties = {
        'created': Property(default=lambda: NOW),
        'external_references': Property(),
        'created_by_ref': ReferenceProperty(type="identity"),
        'object_marking_refs': ListProperty(ReferenceProperty(type="marking-definition")),
        'granular_marking': ListProperty(GranularMarking),
        'type': TypeProperty(_type),
        'id': IDProperty(_type),
        'definition_type': Property(),
        'definition': Property(),
    }


class TLPMarking(_STIXBase):
    # TODO: don't allow the creation of any other TLPMarkings than the ones below
    _properties = {
        'tlp': Property(required=True)
    }


class StatementMarking(_STIXBase):
    _properties = {
        'statement': Property(required=True)
    }

    def __init__(self, statement=None, **kwargs):
        # Allow statement as positional args.
        if statement and not kwargs.get('statement'):
            kwargs['statement'] = statement

        super(StatementMarking, self).__init__(**kwargs)


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
