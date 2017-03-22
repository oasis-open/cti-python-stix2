"""STIX 2.0 Domain Objects"""

from .base import _STIXBase
from .common import COMMON_PROPERTIES
from .properties import IDProperty, TypeProperty, Property
from .utils import NOW


class AttackPattern(_STIXBase):

    _type = 'attack-pattern'
    _properties = COMMON_PROPERTIES.copy()
    _properties.update({
        'type': TypeProperty(_type),
        'id': IDProperty(_type),
        'name': Property(required=True),
        'description': Property(),
        'kill_chain_phases': Property(),
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


class Campaign(_STIXBase):

    _type = 'campaign'
    _properties = COMMON_PROPERTIES.copy()
    _properties.update({
        'type': TypeProperty(_type),
        'id': IDProperty(_type),
        'name': Property(required=True),
        'description': Property(),
        'aliases': Property(),
        'first_seen': Property(),
        'last_seen': Property(),
        'objective': Property(),
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
        # - objective

        super(Campaign, self).__init__(**kwargs)


class CourseOfAction(_STIXBase):

    _type = 'course-of-action'
    _properties = COMMON_PROPERTIES.copy()
    _properties.update({
        'type': TypeProperty(_type),
        'id': IDProperty(_type),
        'name': Property(required=True),
        'description': Property(),
    })

    def __init__(self, **kwargs):
        # TODO:
        # - created_by_ref
        # - external_references
        # - object_marking_refs
        # - granular_markings

        # - description

        super(CourseOfAction, self).__init__(**kwargs)


class Identity(_STIXBase):

    _type = 'identity'
    _properties = COMMON_PROPERTIES.copy()
    _properties.update({
        'type': TypeProperty(_type),
        'id': IDProperty(_type),
        'name': Property(required=True),
        'description': Property(),
        'identity_class': Property(required=True),
        'sectors': Property(),
        'contact_information': Property(),
    })

    def __init__(self, **kwargs):
        # TODO:
        # - created_by_ref
        # - external_references
        # - object_marking_refs
        # - granular_markings

        # - description
        # - identity_class
        # - sectors
        # - contact_information

        super(Identity, self).__init__(**kwargs)


class Indicator(_STIXBase):

    _type = 'indicator'
    _properties = COMMON_PROPERTIES.copy()
    _properties.update({
        'type': TypeProperty(_type),
        'id': IDProperty(_type),
        'labels': Property(required=True),
        'name': Property(),
        'description': Property(),
        'pattern': Property(required=True),
        'valid_from': Property(default=lambda: NOW),
        'valid_until': Property(),
        'kill_chain_phases': Property(),
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
        'type': TypeProperty(_type),
        'id': IDProperty(_type),
        'name': Property(required=True),
        'description': Property(),
        'aliases': Property(),
        'first_seen': Property(),
        'last_seen ': Property(),
        'goals': Property(),
        'resource_level': Property(),
        'primary_motivation': Property(),
        'secondary_motivations': Property(),
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
        'type': TypeProperty(_type),
        'id': IDProperty(_type),
        'labels': Property(required=True),
        'name': Property(required=True),
        'description': Property(),
        'kill_chain_phases': Property(),
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


class ObservedData(_STIXBase):

    _type = 'observed-data'
    _properties = COMMON_PROPERTIES.copy()
    _properties.update({
        'type': TypeProperty(_type),
        'id': IDProperty(_type),
        'first_observed': Property(),
        'last_observed': Property(),
        'number_observed': Property(),
        'objects': Property(),
    })

    def __init__(self, **kwargs):
        # TODO:
        # - created_by_ref
        # - external_references
        # - object_marking_refs
        # - granular_markings

        # - first_observed
        # - last_observed
        # - number_observed
        # - objects

        super(ObservedData, self).__init__(**kwargs)


class Report(_STIXBase):

    _type = 'report'
    _properties = COMMON_PROPERTIES.copy()
    _properties.update({
        'type': TypeProperty(_type),
        'id': IDProperty(_type),
        'labels': Property(required=True),
        'name': Property(required=True),
        'description': Property(),
        'published': Property(),
        'object_refs': Property(),
    })

    def __init__(self, **kwargs):
        # TODO:
        # - created_by_ref
        # - external_references
        # - object_marking_refs
        # - granular_markings

        # - description
        # - published
        # - object_refs

        super(Report, self).__init__(**kwargs)


class ThreatActor(_STIXBase):

    _type = 'threat-actor'
    _properties = COMMON_PROPERTIES.copy()
    _properties.update({
        'type': TypeProperty(_type),
        'id': IDProperty(_type),
        'labels': Property(required=True),
        'name': Property(required=True),
        'description': Property(),
        'aliases': Property(),
        'roles': Property(),
        'goals': Property(),
        'sophistication': Property(),
        'resource_level': Property(),
        'primary_motivation': Property(),
        'secondary_motivations': Property(),
        'personal_motivations': Property(),
    })

    def __init__(self, **kwargs):
        # TODO:
        # - created_by_ref
        # - external_references
        # - object_marking_refs
        # - granular_markings

        # - description
        # - aliases
        # - roles
        # - goals
        # - sophistication
        # - resource_level
        # - primary_motivation
        # - secondary_motivations
        # - personal_motivations

        super(ThreatActor, self).__init__(**kwargs)


class Tool(_STIXBase):

    _type = 'tool'
    _properties = COMMON_PROPERTIES.copy()
    _properties.update({
        'type': TypeProperty(_type),
        'id': IDProperty(_type),
        'labels': Property(required=True),
        'name': Property(required=True),
        'description': Property(),
        'kill_chain_phases': Property(),
        'tool_version': Property(),
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


class Vulnerability(_STIXBase):

    _type = 'vulnerability'
    _properties = COMMON_PROPERTIES.copy()
    _properties.update({
        'type': TypeProperty(_type),
        'id': IDProperty(_type),
        'name': Property(required=True),
        'description': Property(),
    })

    def __init__(self, **kwargs):
        # TODO:
        # - created_by_ref
        # - external_references
        # - object_marking_refs
        # - granular_markings

        # - description

        super(Vulnerability, self).__init__(**kwargs)
