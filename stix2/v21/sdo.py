"""STIX 2.1 Domain Objects."""

from collections import OrderedDict
import itertools
import warnings

from six.moves.urllib.parse import quote_plus
from stix2patterns.validator import run_validator

from ..core import STIXDomainObject
from ..custom import _custom_object_builder
from ..exceptions import (
    InvalidValueError, PropertyPresenceError, STIXDeprecationWarning,
)
from ..properties import (
    BinaryProperty, BooleanProperty, EmbeddedObjectProperty, EnumProperty,
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
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('name', StringProperty(required=True)),
        ('description', StringProperty()),
        ('aliases', ListProperty(StringProperty)),
        ('kill_chain_phases', ListProperty(KillChainPhase)),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
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
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
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
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
    ])

    def _check_object_constraints(self):
        super(Campaign, self)._check_object_constraints()

        first_seen = self.get('first_seen')
        last_seen = self.get('last_seen')

        if first_seen and last_seen and last_seen < first_seen:
            msg = "{0.id} 'last_seen' must be greater than or equal 'first_seen'"
            raise ValueError(msg.format(self))


class CourseOfAction(STIXDomainObject):
    # TODO: Add link
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <link here>`__.
    """

    _type = 'course-of-action'
    _properties = OrderedDict([
        ('type', TypeProperty(_type)),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('name', StringProperty(required=True)),
        ('description', StringProperty()),
        ('action_type', StringProperty()),
        ('os_execution_envs', ListProperty(StringProperty)),
        ('action_bin', BinaryProperty()),
        ('action_reference', EmbeddedObjectProperty(ExternalReference)),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
    ])

    def _check_object_constraints(self):
        super(CourseOfAction, self)._check_object_constraints()

        self._check_mutually_exclusive_properties(
            ["action_bin", "action_reference"],
            at_least_one=False,
        )


class Grouping(STIXDomainObject):
    # TODO: Add link
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <link here>`__.
    """

    _type = 'grouping'
    _properties = OrderedDict([
        ('type', TypeProperty(_type)),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('name', StringProperty()),
        ('description', StringProperty()),
        ('context', StringProperty(required=True)),
        ('object_refs', ListProperty(ReferenceProperty(valid_types=["SCO", "SDO", "SRO"], spec_version='2.1'), required=True)),
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
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('name', StringProperty(required=True)),
        ('description', StringProperty()),
        ('roles', ListProperty(StringProperty)),
        ('identity_class', StringProperty(required=True)),
        ('sectors', ListProperty(StringProperty)),
        ('contact_information', StringProperty()),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
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
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('name', StringProperty()),
        ('description', StringProperty()),
        ('indicator_types', ListProperty(StringProperty, required=True)),
        ('pattern', PatternProperty(required=True)),
        ('pattern_type', StringProperty(required=True)),
        ('pattern_version', StringProperty()),
        ('valid_from', TimestampProperty(default=lambda: NOW, required=True)),
        ('valid_until', TimestampProperty()),
        ('kill_chain_phases', ListProperty(KillChainPhase)),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
    ])

    def __init__(self, *args, **kwargs):

        if kwargs.get('pattern') and kwargs.get('pattern_type') == 'stix' and not kwargs.get('pattern_version'):
            kwargs['pattern_version'] = '2.1'

        super(STIXDomainObject, self).__init__(*args, **kwargs)

    def _check_object_constraints(self):
        super(Indicator, self)._check_object_constraints()

        valid_from = self.get('valid_from')
        valid_until = self.get('valid_until')

        if valid_from and valid_until and valid_until <= valid_from:
            msg = "{0.id} 'valid_until' must be greater than 'valid_from'"
            raise ValueError(msg.format(self))

        if self.get('pattern_type') == "stix":
            try:
                pat_ver = self.get('pattern_version')
            except AttributeError:
                pat_ver = '2.1'

            errors = run_validator(self.get('pattern'), pat_ver)
            if errors:
                raise InvalidValueError(self.__class__, 'pattern', str(errors[0]))


class Infrastructure(STIXDomainObject):
    # TODO: Add link
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <link here>`__.
    """

    _type = 'infrastructure'
    _properties = OrderedDict([
        ('type', TypeProperty(_type)),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('name', StringProperty(required=True)),
        ('description', StringProperty()),
        ('infrastructure_types', ListProperty(StringProperty, required=True)),
        ('aliases', ListProperty(StringProperty)),
        ('kill_chain_phases', ListProperty(KillChainPhase)),
        ('first_seen', TimestampProperty()),
        ('last_seen', TimestampProperty()),
    ])

    def _check_object_constraints(self):
        super(Infrastructure, self)._check_object_constraints()

        first_seen = self.get('first_seen')
        last_seen = self.get('last_seen')

        if first_seen and last_seen and last_seen < first_seen:
            msg = "{0.id} 'last_seen' must be greater than or equal to 'first_seen'"
            raise ValueError(msg.format(self))


class IntrusionSet(STIXDomainObject):
    # TODO: Add link
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <link here>`__.
    """

    _type = 'intrusion-set'
    _properties = OrderedDict([
        ('type', TypeProperty(_type)),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
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
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
    ])

    def _check_object_constraints(self):
        super(IntrusionSet, self)._check_object_constraints()

        first_seen = self.get('first_seen')
        last_seen = self.get('last_seen')

        if first_seen and last_seen and last_seen < first_seen:
            msg = "{0.id} 'last_seen' must be greater than or equal to 'first_seen'"
            raise ValueError(msg.format(self))


class Location(STIXDomainObject):
    # TODO: Add link
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <link here>`__.
    """

    _type = 'location'
    _properties = OrderedDict([
        ('type', TypeProperty(_type)),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('name', StringProperty()),
        ('description', StringProperty()),
        ('latitude', FloatProperty(min=-90.0, max=90.0)),
        ('longitude', FloatProperty(min=-180.0, max=180.0)),
        ('precision', FloatProperty(min=0.0)),
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
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
    ])

    def _check_object_constraints(self):
        super(Location, self)._check_object_constraints()

        if self.get('precision') is not None:
            self._check_properties_dependency(['longitude', 'latitude'], ['precision'])

        self._check_properties_dependency(['latitude'], ['longitude'])
        self._check_properties_dependency(['longitude'], ['latitude'])

        if not (
            'region' in self
            or 'country' in self
            or (
                'latitude' in self
                and 'longitude' in self
            )
        ):
            raise PropertyPresenceError(
                "Location objects must have the properties 'region', "
                "'country', or 'latitude' and 'longitude'",
                Location,
            )

    def to_maps_url(self, map_engine="Google Maps"):
        """Return URL to this location in an online map engine.

        Google Maps is the default, but Bing maps are also supported.

        Args:
            map_engine (str): Which map engine to find the location in

        Returns:
            The URL of the location in the given map engine.

        """
        params = []

        latitude = self.get('latitude', None)
        longitude = self.get('longitude', None)
        if latitude is not None and longitude is not None:
            params.extend([str(latitude), str(longitude)])
        else:
            properties = ['street_address', 'city', 'country', 'region', 'administrative_area', 'postal_code']
            params = [self.get(prop) for prop in properties if self.get(prop) is not None]

        return self._to_maps_url_dispatcher(map_engine, params)

    def _to_maps_url_dispatcher(self, map_engine, params):
        if map_engine == "Google Maps":
            return self._to_google_maps_url(params)
        elif map_engine == "Bing Maps":
            return self._to_bing_maps_url(params)
        else:
            raise ValueError(map_engine + " is not a valid or currently-supported map engine")

    def _to_google_maps_url(self, params):
        url_base = "https://www.google.com/maps/search/?api=1&query="
        url_ending = params[0]
        for i in range(1, len(params)):
            url_ending = url_ending + "," + params[i]

        final_url = url_base + quote_plus(url_ending)
        return final_url

    def _to_bing_maps_url(self, params):
        url_base = "https://bing.com/maps/default.aspx?where1="
        url_ending = params[0]
        for i in range(1, len(params)):
            url_ending = url_ending + "," + params[i]

        final_url = url_base + quote_plus(url_ending) + "&lvl=16"   # level 16 zoom so long/lat searches shown more clearly
        return final_url


class Malware(STIXDomainObject):
    # TODO: Add link
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <link here>`__.
    """

    _type = 'malware'
    _properties = OrderedDict([
        ('type', TypeProperty(_type)),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('name', StringProperty()),
        ('description', StringProperty()),
        ('malware_types', ListProperty(StringProperty, required=True)),
        ('is_family', BooleanProperty(required=True)),
        ('aliases', ListProperty(StringProperty)),
        ('kill_chain_phases', ListProperty(KillChainPhase)),
        ('first_seen', TimestampProperty()),
        ('last_seen', TimestampProperty()),
        ('os_execution_envs', ListProperty(StringProperty)),
        ('architecture_execution_envs', ListProperty(StringProperty)),
        ('implementation_languages', ListProperty(StringProperty)),
        ('capabilities', ListProperty(StringProperty)),
        ('sample_refs', ListProperty(ReferenceProperty(valid_types=['artifact', 'file'], spec_version='2.1'))),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
    ])

    def _check_object_constraints(self):
        super(Malware, self)._check_object_constraints()

        first_seen = self.get('first_seen')
        last_seen = self.get('last_seen')

        if first_seen and last_seen and last_seen < first_seen:
            msg = "{0.id} 'last_seen' must be greater than or equal to 'first_seen'"
            raise ValueError(msg.format(self))

        if self.is_family and "name" not in self:
            raise PropertyPresenceError(
                "'name' is a required property for malware families",
                Malware,
            )


class MalwareAnalysis(STIXDomainObject):
    # TODO: Add link
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <link here>`__.
    """

    _type = 'malware-analysis'
    _properties = OrderedDict([
        ('type', TypeProperty(_type)),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
        ('product', StringProperty(required=True)),
        ('version', StringProperty()),
        ('host_vm_ref', ReferenceProperty(valid_types='software', spec_version='2.1')),
        ('operating_system_ref', ReferenceProperty(valid_types='software', spec_version='2.1')),
        ('installed_software_refs', ListProperty(ReferenceProperty(valid_types='software', spec_version='2.1'))),
        ('configuration_version', StringProperty()),
        ('modules', ListProperty(StringProperty)),
        ('analysis_engine_version', StringProperty()),
        ('analysis_definition_version', StringProperty()),
        ('submitted', TimestampProperty()),
        ('analysis_started', TimestampProperty()),
        ('analysis_ended', TimestampProperty()),
        ('av_result', StringProperty()),
        ('analysis_sco_refs', ListProperty(ReferenceProperty(valid_types="SCO", spec_version='2.1'))),
    ])

    def _check_object_constraints(self):
        super(MalwareAnalysis, self)._check_object_constraints()

        self._check_at_least_one_property(["av_result", "analysis_sco_refs"])


class Note(STIXDomainObject):
    # TODO: Add link
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <link here>`__.
    """

    _type = 'note'
    _properties = OrderedDict([
        ('type', TypeProperty(_type)),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('abstract', StringProperty()),
        ('content', StringProperty(required=True)),
        ('authors', ListProperty(StringProperty)),
        ('object_refs', ListProperty(ReferenceProperty(valid_types=["SCO", "SDO", "SRO"], spec_version='2.1'), required=True)),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
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
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('first_observed', TimestampProperty(required=True)),
        ('last_observed', TimestampProperty(required=True)),
        ('number_observed', IntegerProperty(min=1, max=999999999, required=True)),
        ('objects', ObservableProperty(spec_version='2.1')),
        ('object_refs', ListProperty(ReferenceProperty(valid_types=["SCO", "SRO"], spec_version="2.1"))),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
    ])

    def __init__(self, *args, **kwargs):
        self._allow_custom = kwargs.get('allow_custom', False)
        self._properties['objects'].allow_custom = kwargs.get('allow_custom', False)

        if "objects" in kwargs:
            warnings.warn(
                "The 'objects' property of observed-data is deprecated in "
                "STIX 2.1.",
                STIXDeprecationWarning,
            )

        super(ObservedData, self).__init__(*args, **kwargs)

    def _check_object_constraints(self):
        super(ObservedData, self)._check_object_constraints()

        first_observed = self.get('first_observed')
        last_observed = self.get('last_observed')

        if first_observed and last_observed and last_observed < first_observed:
            msg = "{0.id} 'last_observed' must be greater than or equal to 'first_observed'"
            raise ValueError(msg.format(self))

        self._check_mutually_exclusive_properties(
            ["objects", "object_refs"],
        )


class Opinion(STIXDomainObject):
    # TODO: Add link
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <link here>`__.
    """

    _type = 'opinion'
    _properties = OrderedDict([
        ('type', TypeProperty(_type)),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('explanation', StringProperty()),
        ('authors', ListProperty(StringProperty)),
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
        ('object_refs', ListProperty(ReferenceProperty(valid_types=["SCO", "SDO", "SRO"], spec_version='2.1'), required=True)),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
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
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('name', StringProperty(required=True)),
        ('description', StringProperty()),
        ('report_types', ListProperty(StringProperty, required=True)),
        ('published', TimestampProperty(required=True)),
        ('object_refs', ListProperty(ReferenceProperty(valid_types=["SCO", "SDO", "SRO"], spec_version='2.1'), required=True)),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
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
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('name', StringProperty(required=True)),
        ('description', StringProperty()),
        ('threat_actor_types', ListProperty(StringProperty, required=True)),
        ('aliases', ListProperty(StringProperty)),
        ('first_seen', TimestampProperty()),
        ('last_seen', TimestampProperty()),
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
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
        ('granular_markings', ListProperty(GranularMarking)),
    ])

    def _check_object_constraints(self):
        super(ThreatActor, self)._check_object_constraints()

        first_observed = self.get('first_seen')
        last_observed = self.get('last_seen')

        if first_observed and last_observed and last_observed < first_observed:
            msg = "{0.id} 'last_seen' must be greater than or equal to 'first_seen'"
            raise ValueError(msg.format(self))


class Tool(STIXDomainObject):
    # TODO: Add link
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <link here>`__.
    """

    _type = 'tool'
    _properties = OrderedDict([
        ('type', TypeProperty(_type)),
        ('spec_version', StringProperty(fixed='2.1')),
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('name', StringProperty(required=True)),
        ('description', StringProperty()),
        ('tool_types', ListProperty(StringProperty, required=True)),
        ('aliases', ListProperty(StringProperty)),
        ('kill_chain_phases', ListProperty(KillChainPhase)),
        ('tool_version', StringProperty()),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
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
        ('id', IDProperty(_type, spec_version='2.1')),
        ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
        ('created', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('modified', TimestampProperty(default=lambda: NOW, precision='millisecond')),
        ('name', StringProperty(required=True)),
        ('description', StringProperty()),
        ('revoked', BooleanProperty(default=lambda: False)),
        ('labels', ListProperty(StringProperty)),
        ('confidence', IntegerProperty()),
        ('lang', StringProperty()),
        ('external_references', ListProperty(ExternalReference)),
        ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
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
                ('id', IDProperty(type, spec_version='2.1')),
                ('created_by_ref', ReferenceProperty(valid_types='identity', spec_version='2.1')),
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
                ('object_marking_refs', ListProperty(ReferenceProperty(valid_types='marking-definition', spec_version='2.1'))),
                ('granular_markings', ListProperty(GranularMarking)),
            ],
            sorted([x for x in properties if x[0].startswith('x_')], key=lambda x: x[0]),
        ]))
        return _custom_object_builder(cls, type, _properties, '2.1')

    return wrapper
