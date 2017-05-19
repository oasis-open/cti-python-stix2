"""STIX 2.0 Domain Objects"""

from .base import _STIXBase
from .common import COMMON_PROPERTIES
from .other import KillChainPhase
from .properties import (IDProperty, IntegerProperty, ListProperty,
                         ObservableProperty, ReferenceProperty, StringProperty,
                         TimestampProperty, TypeProperty)
from .utils import NOW


class AttackPattern(_STIXBase):

    _type = 'attack-pattern'
    _properties = COMMON_PROPERTIES.copy()
    _properties.update({
        'type': TypeProperty(_type),
        'id': IDProperty(_type),
        'name': StringProperty(required=True),
        'description': StringProperty(),
        'kill_chain_phases': ListProperty(KillChainPhase),
    })


class Campaign(_STIXBase):

    _type = 'campaign'
    _properties = COMMON_PROPERTIES.copy()
    _properties.update({
        'type': TypeProperty(_type),
        'id': IDProperty(_type),
        'name': StringProperty(required=True),
        'description': StringProperty(),
        'aliases': ListProperty(StringProperty),
        'first_seen': TimestampProperty(),
        'last_seen': TimestampProperty(),
        'objective': StringProperty(),
    })


class CourseOfAction(_STIXBase):

    _type = 'course-of-action'
    _properties = COMMON_PROPERTIES.copy()
    _properties.update({
        'type': TypeProperty(_type),
        'id': IDProperty(_type),
        'name': StringProperty(required=True),
        'description': StringProperty(),
    })


class Identity(_STIXBase):

    _type = 'identity'
    _properties = COMMON_PROPERTIES.copy()
    _properties.update({
        'type': TypeProperty(_type),
        'id': IDProperty(_type),
        'name': StringProperty(required=True),
        'description': StringProperty(),
        'identity_class': StringProperty(required=True),
        'sectors': ListProperty(StringProperty),
        'contact_information': StringProperty(),
    })


class Indicator(_STIXBase):

    _type = 'indicator'
    _properties = COMMON_PROPERTIES.copy()
    _properties.update({
        'type': TypeProperty(_type),
        'id': IDProperty(_type),
        'labels': ListProperty(StringProperty, required=True),
        'name': StringProperty(),
        'description': StringProperty(),
        'pattern': StringProperty(required=True),
        'valid_from': TimestampProperty(default=lambda: NOW),
        'valid_until': TimestampProperty(),
        'kill_chain_phases': ListProperty(KillChainPhase),
    })


class IntrusionSet(_STIXBase):

    _type = 'intrusion-set'
    _properties = COMMON_PROPERTIES.copy()
    _properties.update({
        'type': TypeProperty(_type),
        'id': IDProperty(_type),
        'name': StringProperty(required=True),
        'description': StringProperty(),
        'aliases': ListProperty(StringProperty),
        'first_seen': TimestampProperty(),
        'last_seen ': TimestampProperty(),
        'goals': ListProperty(StringProperty),
        'resource_level': StringProperty(),
        'primary_motivation': StringProperty(),
        'secondary_motivations': ListProperty(StringProperty),
    })


class Malware(_STIXBase):

    _type = 'malware'
    _properties = COMMON_PROPERTIES.copy()
    _properties.update({
        'type': TypeProperty(_type),
        'id': IDProperty(_type),
        'labels': ListProperty(StringProperty, required=True),
        'name': StringProperty(required=True),
        'description': StringProperty(),
        'kill_chain_phases': ListProperty(KillChainPhase),
    })


class ObservedData(_STIXBase):

    _type = 'observed-data'
    _properties = COMMON_PROPERTIES.copy()
    _properties.update({
        'type': TypeProperty(_type),
        'id': IDProperty(_type),
        'first_observed': TimestampProperty(required=True),
        'last_observed': TimestampProperty(required=True),
        'number_observed': IntegerProperty(required=True),
        'objects': ObservableProperty(),
    })


class Report(_STIXBase):

    _type = 'report'
    _properties = COMMON_PROPERTIES.copy()
    _properties.update({
        'type': TypeProperty(_type),
        'id': IDProperty(_type),
        'labels': ListProperty(StringProperty, required=True),
        'name': StringProperty(required=True),
        'description': StringProperty(),
        'published': TimestampProperty(),
        'object_refs': ListProperty(ReferenceProperty),
    })


class ThreatActor(_STIXBase):

    _type = 'threat-actor'
    _properties = COMMON_PROPERTIES.copy()
    _properties.update({
        'type': TypeProperty(_type),
        'id': IDProperty(_type),
        'labels': ListProperty(StringProperty, required=True),
        'name': StringProperty(required=True),
        'description': StringProperty(),
        'aliases': ListProperty(StringProperty),
        'roles': ListProperty(StringProperty),
        'goals': ListProperty(StringProperty),
        'sophistication': StringProperty(),
        'resource_level': StringProperty(),
        'primary_motivation': StringProperty(),
        'secondary_motivations': ListProperty(StringProperty),
        'personal_motivations': ListProperty(StringProperty),
    })


class Tool(_STIXBase):

    _type = 'tool'
    _properties = COMMON_PROPERTIES.copy()
    _properties.update({
        'type': TypeProperty(_type),
        'id': IDProperty(_type),
        'labels': ListProperty(StringProperty, required=True),
        'name': StringProperty(required=True),
        'description': StringProperty(),
        'kill_chain_phases': ListProperty(KillChainPhase),
        'tool_version': StringProperty(),
    })


class Vulnerability(_STIXBase):

    _type = 'vulnerability'
    _properties = COMMON_PROPERTIES.copy()
    _properties.update({
        'type': TypeProperty(_type),
        'id': IDProperty(_type),
        'name': StringProperty(required=True),
        'description': StringProperty(),
    })
