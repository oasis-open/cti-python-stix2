from collections import OrderedDict

from stix2 import parse
from stix2.base import _STIXBase
from stix2.properties import TypeProperty, IDProperty, ListProperty, Property
from stix2.utils import get_class_hierarchy_names, _get_dict


class STIXObjectProperty(Property):

    def __init__(self, allow_custom=False, *args, **kwargs):
        self.allow_custom = allow_custom
        super(STIXObjectProperty, self).__init__(*args, **kwargs)

    def clean(self, value):
        # Any STIX Object (SDO, SRO, or Marking Definition) can be added to
        # a bundle with no further checks.
        if any(x in ('STIXDomainObject', 'STIXRelationshipObject', 'MarkingDefinition')
               for x in get_class_hierarchy_names(value)):
            return value
        try:
            dictified = _get_dict(value)
        except ValueError:
            raise ValueError("This property may only contain a dictionary or object")
        if dictified == {}:
            raise ValueError("This property may only contain a non-empty dictionary or object")
        if 'type' in dictified and dictified['type'] == 'bundle':
            raise ValueError('This property may not contain a Bundle object')

        parsed_obj = parse(dictified, allow_custom=self.allow_custom)

        return parsed_obj


class Bundle(_STIXBase):
    """For more detailed information on this object's properties, see
    TODO: Update this to a STIX 2.1 link.
    `the STIX 2.0 specification <http://docs.oasis-open.org/cti/stix/v2.0/cs01/part1-stix-core/stix-v2.0-cs01-part1-stix-core.html#_Toc496709293>`__.
    """

    _type = 'bundle'
    _properties = OrderedDict()
    _properties.update([
        ('type', TypeProperty(_type)),
        ('id', IDProperty(_type)),
        ('objects', ListProperty(STIXObjectProperty)),
    ])

    def __init__(self, *args, **kwargs):
        # Add any positional arguments to the 'objects' kwarg.
        if args:
            if isinstance(args[0], list):
                kwargs['objects'] = args[0] + list(args[1:]) + kwargs.get('objects', [])
            else:
                kwargs['objects'] = list(args) + kwargs.get('objects', [])

        self.__allow_custom = kwargs.get('allow_custom', False)
        self._properties['objects'].contained.allow_custom = kwargs.get('allow_custom', False)

        super(Bundle, self).__init__(**kwargs)
