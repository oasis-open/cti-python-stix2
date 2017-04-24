"""STIX 2.0 Relationship Objects."""

from .base import _STIXBase
from .common import COMMON_PROPERTIES
from .properties import (IDProperty, IntegerProperty, ListProperty,
                         ReferenceProperty, StringProperty, TimestampProperty,
                         TypeProperty)


class Relationship(_STIXBase):

    _type = 'relationship'
    _properties = COMMON_PROPERTIES.copy()
    _properties.update({
        'id': IDProperty(_type),
        'type': TypeProperty(_type),
        'relationship_type': StringProperty(required=True),
        'description': StringProperty(),
        'source_ref': ReferenceProperty(required=True),
        'target_ref': ReferenceProperty(required=True),
    })

    # Explicitly define the first three kwargs to make readable Relationship declarations.
    def __init__(self, source_ref=None, relationship_type=None, target_ref=None,
                 **kwargs):
        # TODO:
        # - description

        # Allow (source_ref, relationship_type, target_ref) as positional args.
        if source_ref and not kwargs.get('source_ref'):
            kwargs['source_ref'] = source_ref
        if relationship_type and not kwargs.get('relationship_type'):
            kwargs['relationship_type'] = relationship_type
        if target_ref and not kwargs.get('target_ref'):
            kwargs['target_ref'] = target_ref

        super(Relationship, self).__init__(**kwargs)


class Sighting(_STIXBase):
    _type = 'sighting'
    _properties = COMMON_PROPERTIES.copy()
    _properties.update({
        'id': IDProperty(_type),
        'type': TypeProperty(_type),
        'first_seen': TimestampProperty(),
        'last_seen': TimestampProperty(),
        'count': IntegerProperty(),
        'sighting_of_ref': ReferenceProperty(required=True),
        'observed_data_refs': ListProperty(ReferenceProperty(type="observed-data")),
        'where_sighted_refs': ListProperty(ReferenceProperty(type="identity")),
        'summary': StringProperty(),
    })

    # Explicitly define the first kwargs to make readable Sighting declarations.
    def __init__(self, sighting_of_ref=None, **kwargs):
        # TODO:
        # - description

        # Allow sighting_of_ref as a positional arg.
        if sighting_of_ref and not kwargs.get('sighting_of_ref'):
            kwargs['sighting_of_ref'] = sighting_of_ref

        super(Sighting, self).__init__(**kwargs)
