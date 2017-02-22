"""STIX 2.0 Domain Objects"""

from .base import _STIXBase
from .common import COMMON_PROPERTIES
from .utils import NOW


class AttackPattern(_STIXBase):

    _type = 'attack-pattern'
    _properties = COMMON_PROPERTIES.copy()
    _properties.update({
        'labels': {
            'required': True,
        },
        'name': {
            'required': True,
        },
        'description': {},
        'kill_chain_phases': {},
    })

    def __init__(self, **kwargs):
        # TODO:
        # - created_by_ref
        # - external_references
        # - object_marking_refs
        # - granular_markings

        # - description
        # - kill_chain_phases

        super(AttackPattern, self).__init__(**kwargs)


class Indicator(_STIXBase):

    _type = 'indicator'
    _properties = COMMON_PROPERTIES.copy()
    _properties.update({
        'labels': {
            'required': True,
        },
        'name': {},
        'description': {},
        'pattern': {
            'required': True,
        },
        'valid_from': {
            'default': NOW,
        },
        'valid_until': {},
        'kill_chain_phases': {},
    })

    def __init__(self, **kwargs):
        # TODO:
        # - created_by_ref
        # - external_references
        # - object_marking_refs
        # - granular_markings

        # - name
        # - description
        # - valid_until
        # - kill_chain_phases

        super(Indicator, self).__init__(**kwargs)


class IntrusionSet(_STIXBase):

    _type = 'intrusion-set'
    _properties = COMMON_PROPERTIES.copy()
    _properties.update({
        'name': {
            'required': True,
        },
        'description': {},
        'aliases': {},
        'first_seen': {},
        'last_seen ': {},
        'goals': {},
        'resource_level': {},
        'primary_motivation': {},
        'secondary_motivations': {},
    })

    def __init__(self, **kwargs):
        # TODO:
        # - created_by_ref
        # - external_references
        # - object_marking_refs
        # - granular_markings

        # - description
        # - aliases
        # - first_seen
        # - last_seen
        # - goals
        # - resource_level
        # - primary_motivation
        # - secondary_motivations

        super(IntrusionSet, self).__init__(**kwargs)


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
        'description': {},
        'kill_chain_phases': {},
    })

    def __init__(self, **kwargs):
        # TODO:
        # - created_by_ref
        # - external_references
        # - object_marking_refs
        # - granular_markings

        # - description
        # - kill_chain_phases

        super(Malware, self).__init__(**kwargs)


class Tool(_STIXBase):

    _type = 'tool'
    _properties = COMMON_PROPERTIES.copy()
    _properties.update({
        'labels': {
            'required': True,
        },
        'name': {
            'required': True,
        },
        'description': {},
        'kill_chain_phases': {},
        'tool_version': {},
    })

    def __init__(self, **kwargs):
        # TODO:
        # - created_by_ref
        # - external_references
        # - object_marking_refs
        # - granular_markings

        # - description
        # - kill_chain_phases
        # - tool_version

        super(Tool, self).__init__(**kwargs)
