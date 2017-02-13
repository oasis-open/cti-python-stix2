"""STIX 2.0 Relationship Objects."""

from .base import _STIXBase
from .common import COMMON_PROPERTIES


class Relationship(_STIXBase):

    _type = 'relationship'
    _properties = COMMON_PROPERTIES.copy()
    _properties.update({
        'relationship_type': {
            'required': True,
        },
        'source_ref': {
            'required': True,
        },
        'target_ref': {
            'required': True,
        },
    })

    # Explicitly define the first three kwargs to make readable Relationship declarations.
    def __init__(self, source_ref=None, relationship_type=None, target_ref=None,
                 **kwargs):
        # TODO:
        # - created_by_ref
        # - revoked
        # - external_references
        # - object_marking_refs
        # - granular_markings

        # - description

        # Allow (source_ref, relationship_type, target_ref) as positional args.
        if source_ref and not kwargs.get('source_ref'):
            kwargs['source_ref'] = source_ref
        if relationship_type and not kwargs.get('relationship_type'):
            kwargs['relationship_type'] = relationship_type
        if target_ref and not kwargs.get('target_ref'):
            kwargs['target_ref'] = target_ref

        # If actual STIX objects (vs. just the IDs) are passed in, extract the
        # ID values to use in the Relationship object.
        if kwargs.get('source_ref') and isinstance(kwargs['source_ref'], _STIXBase):
            kwargs['source_ref'] = kwargs['source_ref'].id

        if kwargs.get('target_ref') and isinstance(kwargs['target_ref'], _STIXBase):
            kwargs['target_ref'] = kwargs['target_ref'].id

        super(Relationship, self).__init__(**kwargs)
