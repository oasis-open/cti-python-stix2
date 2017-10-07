"""STIX 2.0 Objects that are neither SDOs nor SROs."""

from collections import OrderedDict

from . import exceptions
from .base import _STIXBase
from .common import MarkingDefinition
from .properties import IDProperty, ListProperty, Property, TypeProperty
from .sdo import (AttackPattern, Campaign, CourseOfAction, Identity, Indicator,
                  IntrusionSet, Location, Malware, Note, ObservedData, Opinion,
                  Report, ThreatActor, Tool, Vulnerability)
from .sro import Relationship, Sighting
from .utils import get_dict


class STIXObjectProperty(Property):

    def clean(self, value):
        try:
            dictified = get_dict(value)
        except ValueError:
            raise ValueError("This property may only contain a dictionary or object")
        if dictified == {}:
            raise ValueError("This property may only contain a non-empty dictionary or object")
        if 'type' in dictified and dictified['type'] == 'bundle':
            raise ValueError('This property may not contain a Bundle object')

        parsed_obj = parse(dictified)
        return parsed_obj


class Bundle(_STIXBase):

    _type = 'bundle'
    _properties = OrderedDict()
    _properties.update([
        ('type', TypeProperty(_type)),
        ('id', IDProperty(_type)),
        ('spec_version', Property(fixed="2.0")),
        ('objects', ListProperty(STIXObjectProperty)),
    ])

    def __init__(self, *args, **kwargs):
        # Add any positional arguments to the 'objects' kwarg.
        if args:
            if isinstance(args[0], list):
                kwargs['objects'] = args[0] + list(args[1:]) + kwargs.get('objects', [])
            else:
                kwargs['objects'] = list(args) + kwargs.get('objects', [])

        super(Bundle, self).__init__(**kwargs)


OBJ_MAP = {
    'attack-pattern': AttackPattern,
    'bundle': Bundle,
    'campaign': Campaign,
    'course-of-action': CourseOfAction,
    'identity': Identity,
    'indicator': Indicator,
    'intrusion-set': IntrusionSet,
    'location': Location,
    'malware': Malware,
    'note': Note,
    'marking-definition': MarkingDefinition,
    'observed-data': ObservedData,
    'opinion': Opinion,
    'report': Report,
    'relationship': Relationship,
    'threat-actor': ThreatActor,
    'tool': Tool,
    'sighting': Sighting,
    'vulnerability': Vulnerability,
}


def parse(data, allow_custom=False):
    """Deserialize a string or file-like object into a STIX object.

    Args:
        data (str, dict, file-like object): The STIX 2 content to be parsed.
        allow_custom (bool): Whether to allow custom properties or not. Default: False.

    Returns:
        An instantiated Python STIX object.

    """
    obj = get_dict(data)

    if 'type' not in obj:
        raise exceptions.ParseError("Can't parse object with no 'type' property: %s" % str(obj))

    try:
        obj_class = OBJ_MAP[obj['type']]
    except KeyError:
        raise exceptions.ParseError("Can't parse unknown object type '%s'! For custom types, use the CustomObject decorator." % obj['type'])
    return obj_class(allow_custom=allow_custom, **obj)


def _register_type(new_type):
    """Register a custom STIX Object type.

    """
    OBJ_MAP[new_type._type] = new_type
