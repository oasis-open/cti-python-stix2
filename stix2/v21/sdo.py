"""STIX 2.1 Domain Objects"""

from collections import OrderedDict
import itertools

from ..base import _STIXBase
from ..core import STIXDomainObject
from ..custom import _custom_object_builder
from ..properties import (
    BooleanProperty, DictionaryProperty, EmbeddedObjectProperty, EnumProperty,
    FloatProperty, IDProperty, IntegerProperty, ListProperty,
    ObservableProperty, PatternProperty, ReferenceProperty, StringProperty,
    TimestampProperty, TypeProperty,
)
from ..utils import NOW
from .common import ExternalReference, GranularMarking, KillChainPhase


class AttackPattern(STIXDomainObject):
    # TODO: Add link
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <link here>`__.
    """

    _type = 'attack-pattern'
    _properties = OrderedDict([
        ('type', TypeProperty(_type)),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type)),
        ('created_by_ref', ReferenceProperty(type='identity')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('name', StringProperty(required=True)),
        ('description', StringProperty()),
        ('kill_chain_phases', ListProperty(KillChainPhase)),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(type='marking-definition'))),
        ('granular_markings', ListProperty(GranularMarking)),
    ])


class Campaign(STIXDomainObject):
    # TODO: Add link
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <link here>`__.
    """

    _type = 'campaign'
    _properties = OrderedDict([
        ('type', TypeProperty(_type)),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type)),
        ('created_by_ref', ReferenceProperty(type='identity')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('name', StringProperty(required=True)),
        ('description', StringProperty()),
        ('aliases', ListProperty(StringProperty)),
        ('first_seen', TimestampProperty()),
        ('last_seen', TimestampProperty()),
        ('objective', StringProperty()),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(type='marking-definition'))),
        ('granular_markings', ListProperty(GranularMarking)),
    ])


class CourseOfAction(STIXDomainObject):
    # TODO: Add link
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <link here>`__.
    """

    _type = 'course-of-action'
    _properties = OrderedDict([
        ('type', TypeProperty(_type)),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type)),
        ('created_by_ref', ReferenceProperty(type='identity')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('name', StringProperty(required=True)),
        ('description', StringProperty()),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(type='marking-definition'))),
        ('granular_markings', ListProperty(GranularMarking)),
    ])


class Identity(STIXDomainObject):
    # TODO: Add link
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <link here>`__.
    """

    _type = 'identity'
    _properties = OrderedDict([
        ('type', TypeProperty(_type)),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type)),
        ('created_by_ref', ReferenceProperty(type='identity')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('name', StringProperty(required=True)),
        ('description', StringProperty()),
        ('identity_class', StringProperty(required=True)),
        ('sectors', ListProperty(StringProperty)),
        ('contact_information', StringProperty()),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(type='marking-definition'))),
        ('granular_markings', ListProperty(GranularMarking)),
    ])


class Indicator(STIXDomainObject):
    # TODO: Add link
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <link here>`__.
    """

    _type = 'indicator'
    _properties = OrderedDict([
        ('type', TypeProperty(_type)),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type)),
        ('created_by_ref', ReferenceProperty(type='identity')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('name', StringProperty()),
        ('indicator_types', ListProperty(StringProperty, required=True)),
        ('description', StringProperty()),
        ('pattern', PatternProperty(required=True)),
        ('valid_from', TimestampProperty(default=lambda: NOW)),
        ('valid_until', TimestampProperty()),
        ('kill_chain_phases', ListProperty(KillChainPhase)),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(type='marking-definition'))),
        ('granular_markings', ListProperty(GranularMarking)),
    ])


class IntrusionSet(STIXDomainObject):
    # TODO: Add link
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <link here>`__.
    """

    _type = 'intrusion-set'
    _properties = OrderedDict([
        ('type', TypeProperty(_type)),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type)),
        ('created_by_ref', ReferenceProperty(type='identity')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('name', StringProperty(required=True)),
        ('description', StringProperty()),
        ('aliases', ListProperty(StringProperty)),
        ('first_seen', TimestampProperty()),
        ('last_seen', TimestampProperty()),
        ('goals', ListProperty(StringProperty)),
        ('resource_level', StringProperty()),
        ('primary_motivation', StringProperty()),
        ('secondary_motivations', ListProperty(StringProperty)),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(type='marking-definition'))),
        ('granular_markings', ListProperty(GranularMarking)),
    ])


class Location(STIXDomainObject):
    # TODO: Add link
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <link here>`__.
    """

    _type = 'location'
    _properties = OrderedDict([
        ('type', TypeProperty(_type)),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type)),
        ('created_by_ref', ReferenceProperty(type='identity')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('description', StringProperty()),
        ('latitude', FloatProperty()),
        ('longitude', FloatProperty()),
        ('precision', FloatProperty()),
        ('region', StringProperty()),
        ('country', StringProperty()),
        ('administrative_area', StringProperty()),
        ('city', StringProperty()),
        ('street_address', StringProperty()),
        ('postal_code', StringProperty()),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(type='marking-definition'))),
        ('granular_markings', ListProperty(GranularMarking)),
    ])


class AnalysisType(_STIXBase):

    _properties = OrderedDict([
        ('start_time', TimestampProperty()),
        ('end_time', TimestampProperty()),
        ('analysis_tools', ObservableProperty(spec_version='2.1')),
        ('analysis_environment', DictionaryProperty(spec_version='2.1')),
        ('results', DictionaryProperty(spec_version='2.1', required=True)),
    ])


class AVResultsType(_STIXBase):

    _properties = OrderedDict([
        ('product', StringProperty()),
        ('engine_version', StringProperty()),
        ('definition_version', StringProperty()),
        ('submitted', TimestampProperty()),
        ('scanned', TimestampProperty()),
        ('result', StringProperty()),
        ('details', StringProperty()),
    ])


class Malware(STIXDomainObject):
    # TODO: Add link
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <link here>`__.
    """

    _type = 'malware'
    _properties = OrderedDict([
        ('type', TypeProperty(_type)),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type)),
        ('created_by_ref', ReferenceProperty(type='identity')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('is_family', BooleanProperty(required=True)),
        ('name', StringProperty(required=True)),
        ('malware_types', ListProperty(StringProperty, required=True)),
        ('description', StringProperty()),
        ('kill_chain_phases', ListProperty(KillChainPhase)),
        ('first_seen', TimestampProperty()),
        ('last_seen', TimestampProperty()),
        ('os_execution_envs', ListProperty(StringProperty)),
        ('architecture_execution_envs', ListProperty(StringProperty)),
        ('implementation_languages', ListProperty(StringProperty)),
        ('samples', ObservableProperty(spec_version='2.1')),
        ('static_analysis_results', ListProperty(EmbeddedObjectProperty(AnalysisType))),
        ('dynamic_analysis_results', ListProperty(EmbeddedObjectProperty(AnalysisType))),
        ('av_results', ListProperty(EmbeddedObjectProperty(AVResultsType))),
        ('capabilities', ListProperty(StringProperty)),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(type='marking-definition'))),
        ('granular_markings', ListProperty(GranularMarking)),
    ])


class Note(STIXDomainObject):
    # TODO: Add link
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <link here>`__.
    """

    _type = 'note'
    _properties = OrderedDict([
        ('type', TypeProperty(_type)),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type)),
        ('created_by_ref', ReferenceProperty(type='identity')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('summary', StringProperty()),
        ('description', StringProperty(required=True)),
        ('authors', ListProperty(StringProperty)),
        ('object_refs', ListProperty(ReferenceProperty, required=True)),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(type='marking-definition'))),
        ('granular_markings', ListProperty(GranularMarking)),
    ])


class ObservedData(STIXDomainObject):
    # TODO: Add link
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <link here>`__.
    """

    _type = 'observed-data'
    _properties = OrderedDict([
        ('type', TypeProperty(_type)),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type)),
        ('created_by_ref', ReferenceProperty(type='identity')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('first_observed', TimestampProperty(required=True)),
        ('last_observed', TimestampProperty(required=True)),
        ('number_observed', IntegerProperty(required=True)),
        ('objects', ObservableProperty(spec_version='2.1', required=True)),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(type='marking-definition'))),
        ('granular_markings', ListProperty(GranularMarking)),
    ])

    def __init__(self, *args, **kwargs):
        self.__allow_custom = kwargs.get('allow_custom', False)
        self._properties['objects'].allow_custom = kwargs.get('allow_custom', False)

        super(ObservedData, self).__init__(*args, **kwargs)


class Opinion(STIXDomainObject):
    # TODO: Add link
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <link here>`__.
    """

    _type = 'opinion'
    _properties = OrderedDict([
        ('type', TypeProperty(_type)),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type)),
        ('created_by_ref', ReferenceProperty(type='identity')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('description', StringProperty()),
        ('authors', ListProperty(StringProperty)),
        ('object_refs', ListProperty(ReferenceProperty, required=True)),
        (
            'opinion', EnumProperty(
                allowed=[
                    'strongly-disagree',
                    'disagree',
                    'neutral',
                    'agree',
                    'strongly-agree',
                ], required=True,
            ),
        ),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(type='marking-definition'))),
        ('granular_markings', ListProperty(GranularMarking)),
    ])


class Report(STIXDomainObject):
    # TODO: Add link
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <link here>`__.
    """

    _type = 'report'
    _properties = OrderedDict([
        ('type', TypeProperty(_type)),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type)),
        ('created_by_ref', ReferenceProperty(type='identity')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('name', StringProperty(required=True)),
        ('report_types', ListProperty(StringProperty, required=True)),
        ('description', StringProperty()),
        ('published', TimestampProperty(required=True)),
        ('object_refs', ListProperty(ReferenceProperty, required=True)),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(type='marking-definition'))),
        ('granular_markings', ListProperty(GranularMarking)),
    ])


class ThreatActor(STIXDomainObject):
    # TODO: Add link
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <link here>`__.
    """

    _type = 'threat-actor'
    _properties = OrderedDict([
        ('type', TypeProperty(_type)),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type)),
        ('created_by_ref', ReferenceProperty(type='identity')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('name', StringProperty(required=True)),
        ('threat_actor_types', ListProperty(StringProperty, required=True)),
        ('description', StringProperty()),
        ('aliases', ListProperty(StringProperty)),
        ('roles', ListProperty(StringProperty)),
        ('goals', ListProperty(StringProperty)),
        ('sophistication', StringProperty()),
        ('resource_level', StringProperty()),
        ('primary_motivation', StringProperty()),
        ('secondary_motivations', ListProperty(StringProperty)),
        ('personal_motivations', ListProperty(StringProperty)),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(type='marking-definition'))),
        ('granular_markings', ListProperty(GranularMarking)),
    ])


class Tool(STIXDomainObject):
    # TODO: Add link
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <link here>`__.
    """

    _type = 'tool'
    _properties = OrderedDict([
        ('type', TypeProperty(_type)),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type)),
        ('created_by_ref', ReferenceProperty(type='identity')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('name', StringProperty(required=True)),
        ('tool_types', ListProperty(StringProperty, required=True)),
        ('description', StringProperty()),
        ('kill_chain_phases', ListProperty(KillChainPhase)),
        ('tool_version', StringProperty()),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(type='marking-definition'))),
        ('granular_markings', ListProperty(GranularMarking)),
    ])


class Vulnerability(STIXDomainObject):
    # TODO: Add link
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <link here>`__.
    """

    _type = 'vulnerability'
    _properties = OrderedDict([
        ('type', TypeProperty(_type)),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type)),
        ('created_by_ref', ReferenceProperty(type='identity')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('name', StringProperty(required=True)),
        ('description', StringProperty()),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(type='marking-definition'))),
        ('granular_markings', ListProperty(GranularMarking)),
    ])


def CustomObject(type='x-custom-type', properties=None):
    """Custom STIX Object type decorator.

    Example:
        >>> from stix2.v21 import CustomObject
        >>> from stix2.properties import IntegerProperty, StringProperty
        >>> @CustomObject('x-type-name', [
        ...     ('property1', StringProperty(required=True)),
        ...     ('property2', IntegerProperty()),
        ... ])
        ... class MyNewObjectType():
        ...     pass

    Supply an ``__init__()`` function to add any special validations to the custom
    type. Don't call ``super().__init__()`` though - doing so will cause an error.

    Example:
        >>> from stix2.v21 import CustomObject
        >>> from stix2.properties import IntegerProperty, StringProperty
        >>> @CustomObject('x-type-name', [
        ...     ('property1', StringProperty(required=True)),
        ...     ('property2', IntegerProperty()),
        ... ])
        ... class MyNewObjectType():
        ...     def __init__(self, property2=None, **kwargs):
        ...         if property2 and property2 < 10:
        ...             raise ValueError("'property2' is too small.")

    """
    def wrapper(cls):
        _properties = list(itertools.chain.from_iterable([
            [
                ('type', TypeProperty(type)),
                ('spec_version', StringProperty(fixed='2.1')),
                ('id', IDProperty(type)),
                ('created_by_ref', ReferenceProperty(type='identity')),
                ('created', TimestampProperty(default=lambda: NOW, precision='millisecond')),
                ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond')),
            ],
            [x for x in properties if not x[0].startswith('x_')],
            [
                ('revoked', BooleanProperty(default=lambda: False)),
                ('labels', ListProperty(StringProperty)),
                ('confidence', IntegerProperty()),
                ('lang', StringProperty()),
                ('external_references', ListProperty(ExternalReference)),
                ('object_marking_refs', ListProperty(ReferenceProperty(type='marking-definition'))),
                ('granular_markings', ListProperty(GranularMarking)),
            ],
            sorted([x for x in properties if x[0].startswith('x_')], key=lambda x: x[0]),
        ]))
        return _custom_object_builder(cls, type, _properties, '2.1')

    return wrapper
