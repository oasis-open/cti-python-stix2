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


class CourseOfAction(_STIXBase):

    _type = 'course-of-action'
    _properties = COMMON_PROPERTIES.copy()
    _properties.update({
        'type': TypeProperty(_type),
        'id': IDProperty(_type),
        'name': Property(required=True),
        'description': Property(),
    })


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


class Vulnerability(_STIXBase):

    _type = 'vulnerability'
    _properties = COMMON_PROPERTIES.copy()
    _properties.update({
        'type': TypeProperty(_type),
        'id': IDProperty(_type),
        'name': Property(required=True),
        'description': Property(),
    })
