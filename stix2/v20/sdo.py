"""STIX 2.0 Domain Objects."""

from collections import OrderedDict
import itertools

from ..core import STIXDomainObject
from ..custom import _custom_object_builder
from ..properties import (
    BooleanProperty, IDProperty, IntegerProperty, ListProperty,
    ObservableProperty, PatternProperty, ReferenceProperty, StringProperty,
    TimestampProperty, TypeProperty,
)
from ..utils import NOW
from .common import ExternalReference, GranularMarking, KillChainPhase


class AttackPattern(STIXDomainObject):
    """For more detailed information on this object's properties, see
    `the STIX 2.0 specification <http://docs.oasis-open.org/cti/stix/v2.0/cs01/part2-stix-objects/stix-v2.0-cs01-part2-stix-objects.html#_Toc496714302>`__.
    """

    _type = 'attack-pattern'
    _properties = OrderedDict([
        ('type', TypeProperty(_type)),
        ('id', IDProperty(_type)),
        ('created_by_ref', ReferenceProperty(type='identity')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('name', StringProperty(required=True)),
        ('description', StringProperty()),
        ('kill_chain_phases', ListProperty(KillChainPhase)),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(type='marking-definition'))),
        ('granular_markings', ListProperty(GranularMarking)),
    ])


class Campaign(STIXDomainObject):
    """For more detailed information on this object's properties, see
    `the STIX 2.0 specification <http://docs.oasis-open.org/cti/stix/v2.0/cs01/part2-stix-objects/stix-v2.0-cs01-part2-stix-objects.html#_Toc496714305>`__.
    """

    _type = 'campaign'
    _properties = OrderedDict([
        ('type', TypeProperty(_type)),
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
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(type='marking-definition'))),
        ('granular_markings', ListProperty(GranularMarking)),
    ])


class CourseOfAction(STIXDomainObject):
    """For more detailed information on this object's properties, see
    `the STIX 2.0 specification <http://docs.oasis-open.org/cti/stix/v2.0/cs01/part2-stix-objects/stix-v2.0-cs01-part2-stix-objects.html#_Toc496714308>`__.
    """

    _type = 'course-of-action'
    _properties = OrderedDict([
        ('type', TypeProperty(_type)),
        ('id', IDProperty(_type)),
        ('created_by_ref', ReferenceProperty(type='identity')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('name', StringProperty(required=True)),
        ('description', StringProperty()),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(type='marking-definition'))),
        ('granular_markings', ListProperty(GranularMarking)),
    ])


class Identity(STIXDomainObject):
    """For more detailed information on this object's properties, see
    `the STIX 2.0 specification <http://docs.oasis-open.org/cti/stix/v2.0/cs01/part2-stix-objects/stix-v2.0-cs01-part2-stix-objects.html#_Toc496714311>`__.
    """

    _type = 'identity'
    _properties = OrderedDict([
        ('type', TypeProperty(_type)),
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
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(type='marking-definition'))),
        ('granular_markings', ListProperty(GranularMarking)),
    ])


class Indicator(STIXDomainObject):
    """For more detailed information on this object's properties, see
    `the STIX 2.0 specification <http://docs.oasis-open.org/cti/stix/v2.0/cs01/part2-stix-objects/stix-v2.0-cs01-part2-stix-objects.html#_Toc496714314>`__.
    """

    _type = 'indicator'
    _properties = OrderedDict([
        ('type', TypeProperty(_type)),
        ('id', IDProperty(_type)),
        ('created_by_ref', ReferenceProperty(type='identity')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('name', StringProperty()),
        ('description', StringProperty()),
        ('pattern', PatternProperty(required=True)),
        ('valid_from', TimestampProperty(default=lambda: NOW)),
        ('valid_until', TimestampProperty()),
        ('kill_chain_phases', ListProperty(KillChainPhase)),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty, required=True)),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(type='marking-definition'))),
        ('granular_markings', ListProperty(GranularMarking)),
    ])


class IntrusionSet(STIXDomainObject):
    """For more detailed information on this object's properties, see
    `the STIX 2.0 specification <http://docs.oasis-open.org/cti/stix/v2.0/cs01/part2-stix-objects/stix-v2.0-cs01-part2-stix-objects.html#_Toc496714317>`__.
    """

    _type = 'intrusion-set'
    _properties = OrderedDict([
        ('type', TypeProperty(_type)),
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
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(type='marking-definition'))),
        ('granular_markings', ListProperty(GranularMarking)),
    ])


class Malware(STIXDomainObject):
    """For more detailed information on this object's properties, see
    `the STIX 2.0 specification <http://docs.oasis-open.org/cti/stix/v2.0/cs01/part2-stix-objects/stix-v2.0-cs01-part2-stix-objects.html#_Toc496714320>`__.
    """

    _type = 'malware'
    _properties = OrderedDict([
        ('type', TypeProperty(_type)),
        ('id', IDProperty(_type)),
        ('created_by_ref', ReferenceProperty(type='identity')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('name', StringProperty(required=True)),
        ('description', StringProperty()),
        ('kill_chain_phases', ListProperty(KillChainPhase)),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty, required=True)),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(type='marking-definition'))),
        ('granular_markings', ListProperty(GranularMarking)),
    ])


class ObservedData(STIXDomainObject):
    """For more detailed information on this object's properties, see
    `the STIX 2.0 specification <http://docs.oasis-open.org/cti/stix/v2.0/cs01/part2-stix-objects/stix-v2.0-cs01-part2-stix-objects.html#_Toc496714323>`__.
    """

    _type = 'observed-data'
    _properties = OrderedDict([
        ('type', TypeProperty(_type)),
        ('id', IDProperty(_type)),
        ('created_by_ref', ReferenceProperty(type='identity')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('first_observed', TimestampProperty(required=True)),
        ('last_observed', TimestampProperty(required=True)),
        ('number_observed', IntegerProperty(min=1, max=999999999, required=True)),
        ('objects', ObservableProperty(required=True)),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(type='marking-definition'))),
        ('granular_markings', ListProperty(GranularMarking)),
    ])

    def __init__(self, *args, **kwargs):
        self.__allow_custom = kwargs.get('allow_custom', False)
        self._properties['objects'].allow_custom = kwargs.get('allow_custom', False)

        super(ObservedData, self).__init__(*args, **kwargs)


class Report(STIXDomainObject):
    """For more detailed information on this object's properties, see
    `the STIX 2.0 specification <http://docs.oasis-open.org/cti/stix/v2.0/cs01/part2-stix-objects/stix-v2.0-cs01-part2-stix-objects.html#_Toc496714326>`__.
    """

    _type = 'report'
    _properties = OrderedDict([
        ('type', TypeProperty(_type)),
        ('id', IDProperty(_type)),
        ('created_by_ref', ReferenceProperty(type='identity')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('name', StringProperty(required=True)),
        ('description', StringProperty()),
        ('published', TimestampProperty(required=True)),
        ('object_refs', ListProperty(ReferenceProperty, required=True)),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty, required=True)),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(type='marking-definition'))),
        ('granular_markings', ListProperty(GranularMarking)),
    ])


class ThreatActor(STIXDomainObject):
    """For more detailed information on this object's properties, see
    `the STIX 2.0 specification <http://docs.oasis-open.org/cti/stix/v2.0/cs01/part2-stix-objects/stix-v2.0-cs01-part2-stix-objects.html#_Toc496714329>`__.
    """

    _type = 'threat-actor'
    _properties = OrderedDict([
        ('type', TypeProperty(_type)),
        ('id', IDProperty(_type)),
        ('created_by_ref', ReferenceProperty(type='identity')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('name', StringProperty(required=True)),
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
        ('labels', ListProperty(StringProperty, required=True)),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(type='marking-definition'))),
        ('granular_markings', ListProperty(GranularMarking)),
    ])


class Tool(STIXDomainObject):
    """For more detailed information on this object's properties, see
    `the STIX 2.0 specification <http://docs.oasis-open.org/cti/stix/v2.0/cs01/part2-stix-objects/stix-v2.0-cs01-part2-stix-objects.html#_Toc496714332>`__.
    """

    _type = 'tool'
    _properties = OrderedDict([
        ('type', TypeProperty(_type)),
        ('id', IDProperty(_type)),
        ('created_by_ref', ReferenceProperty(type='identity')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('name', StringProperty(required=True)),
        ('description', StringProperty()),
        ('kill_chain_phases', ListProperty(KillChainPhase)),
        ('tool_version', StringProperty()),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty, required=True)),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(type='marking-definition'))),
        ('granular_markings', ListProperty(GranularMarking)),
    ])


class Vulnerability(STIXDomainObject):
    """For more detailed information on this object's properties, see
    `the STIX 2.0 specification <http://docs.oasis-open.org/cti/stix/v2.0/cs01/part2-stix-objects/stix-v2.0-cs01-part2-stix-objects.html#_Toc496714335>`__.
    """

    _type = 'vulnerability'
    _properties = OrderedDict([
        ('type', TypeProperty(_type)),
        ('id', IDProperty(_type)),
        ('created_by_ref', ReferenceProperty(type='identity')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('name', StringProperty(required=True)),
        ('description', StringProperty()),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(type='marking-definition'))),
        ('granular_markings', ListProperty(GranularMarking)),
    ])


def CustomObject(type='x-custom-type', properties=None):
    """Custom STIX Object type decorator.

    Example:
        >>> from stix2.v20 import CustomObject
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
        >>> from stix2.v20 import CustomObject
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
                ('id', IDProperty(type)),
                ('created_by_ref', ReferenceProperty(type='identity')),
                ('created', TimestampProperty(default=lambda: NOW, precision='millisecond')),
                ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond')),
            ],
            [x for x in properties if not x[0].startswith('x_')],
            [
                ('revoked', BooleanProperty(default=lambda: False)),
                ('labels', ListProperty(StringProperty)),
                ('external_references', ListProperty(ExternalReference)),
                ('object_marking_refs', ListProperty(ReferenceProperty(type='marking-definition'))),
                ('granular_markings', ListProperty(GranularMarking)),
            ],
            sorted([x for x in properties if x[0].startswith('x_')], key=lambda x: x[0]),
        ]))
        return _custom_object_builder(cls, type, _properties, '2.0')
    return wrapper
