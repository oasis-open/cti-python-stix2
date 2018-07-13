"""STIX 2.1 Relationship Objects."""

from collections import OrderedDict

from ..core import STIXRelationshipObject
from ..properties import (
    BooleanProperty, IDProperty, IntegerProperty, ListProperty,
    ReferenceProperty, StringProperty, TimestampProperty, TypeProperty,
)
from ..utils import NOW
from .common import ExternalReference, GranularMarking


class Relationship(STIXRelationshipObject):
    # TODO: Add link
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <link here>`__.
    """

    _type = 'relationship'
    _properties = OrderedDict([
        ('type', TypeProperty(_type)),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type)),
        ('created_by_ref', ReferenceProperty(type='identity')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('relationship_type', StringProperty(required=True)),
        ('description', StringProperty()),
        ('source_ref', ReferenceProperty(required=True)),
        ('target_ref', ReferenceProperty(required=True)),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(type='marking-definition'))),
        ('granular_markings', ListProperty(GranularMarking)),
    ])

    # Explicitly define the first three kwargs to make readable Relationship declarations.
    def __init__(
        self, source_ref=None, relationship_type=None,
        target_ref=None, **kwargs
    ):
        # Allow (source_ref, relationship_type, target_ref) as positional args.
        if source_ref and not kwargs.get('source_ref'):
            kwargs['source_ref'] = source_ref
        if relationship_type and not kwargs.get('relationship_type'):
            kwargs['relationship_type'] = relationship_type
        if target_ref and not kwargs.get('target_ref'):
            kwargs['target_ref'] = target_ref

        super(Relationship, self).__init__(**kwargs)


class Sighting(STIXRelationshipObject):
    # TODO: Add link
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <link here>`__.
    """

    _type = 'sighting'
    _properties = OrderedDict([
        ('type', TypeProperty(_type)),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type)),
        ('created_by_ref', ReferenceProperty(type='identity')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('first_seen', TimestampProperty()),
        ('last_seen', TimestampProperty()),
        ('count', IntegerProperty()),
        ('sighting_of_ref', ReferenceProperty(required=True)),
        ('observed_data_refs', ListProperty(ReferenceProperty(type='observed-data'))),
        ('where_sighted_refs', ListProperty(ReferenceProperty(type='identity'))),
        ('summary', BooleanProperty()),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(type='marking-definition'))),
        ('granular_markings', ListProperty(GranularMarking)),
    ])

    # Explicitly define the first kwargs to make readable Sighting declarations.
    def __init__(self, sighting_of_ref=None, **kwargs):
        # Allow sighting_of_ref as a positional arg.
        if sighting_of_ref and not kwargs.get('sighting_of_ref'):
            kwargs['sighting_of_ref'] = sighting_of_ref

        super(Sighting, self).__init__(**kwargs)
