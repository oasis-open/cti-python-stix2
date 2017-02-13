"""STIX 2.0 Domain Objects"""

from .base import _STIXBase
from .common import COMMON_PROPERTIES
from .utils import NOW


class Indicator(_STIXBase):

    _type = 'indicator'
    _properties = COMMON_PROPERTIES.copy()
    _properties.update({
        'labels': {
            'required': True,
        },
        'pattern': {
            'required': True,
        },
        'valid_from': {
            'default': NOW,
        },
    })

    def __init__(self, **kwargs):
        # TODO:
        # - created_by_ref
        # - revoked
        # - external_references
        # - object_marking_refs
        # - granular_markings

        # - name
        # - description
        # - valid_until
        # - kill_chain_phases

        super(Indicator, self).__init__(**kwargs)


class Malware(_STIXBase):

    _type = 'malware'
    _properties = COMMON_PROPERTIES.copy()
    _properties.update({
        'labels': {
            'required': True,
        },
        'name': {
            'required': True,
        },
    })

    def __init__(self, **kwargs):
        # TODO:
        # - created_by_ref
        # - revoked
        # - external_references
        # - object_marking_refs
        # - granular_markings

        # - description
        # - kill_chain_phases

        super(Malware, self).__init__(**kwargs)
