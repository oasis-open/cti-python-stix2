"""STIX 2.0 Domain Objects"""

import stix2

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


def CustomObject(type='x-custom-type', properties={}):
    """Custom STIX Object type decorator

    Example 1:

    @CustomObject('x-type-name', {
        'property1': StringProperty(required=True),
        'property2': IntegerProperty(),
    })
    class MyNewObjectType():
        pass

    Supply an __init__() function to add any special validations to the custom
    type. Don't call super().__init() though - doing so will cause an error.

    Example 2:

    @CustomObject('x-type-name', {
        'property1': StringProperty(required=True),
        'property2': IntegerProperty(),
    })
    class MyNewObjectType():
        def __init__(self, property2=None, **kwargs):
            if property2 and property2 < 10:
                raise ValueError("'property2' is too small.")
    """

    def custom_builder(cls):

        class _Custom(cls, _STIXBase):
            _type = type
            _properties = COMMON_PROPERTIES.copy()
            _properties.update({
                'id': IDProperty(_type),
                'type': TypeProperty(_type),
            })
            _properties.update(properties)

            def __init__(self, **kwargs):
                _STIXBase.__init__(self, **kwargs)
                cls.__init__(self, **kwargs)

        stix2._register_type(_Custom)
        return _Custom

    return custom_builder
