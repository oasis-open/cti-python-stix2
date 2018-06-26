from collections import OrderedDict

from ..base import _STIXBase
from ..core import parse
from ..utils import _get_dict, get_class_hierarchy_names
from .properties import (IDProperty, ListProperty, Property, StringProperty,
                         TypeProperty)


class STIXObjectProperty(Property):

    def __init__(self, allow_custom=False, *args, **kwargs):
        self.allow_custom = allow_custom
        super(STIXObjectProperty, self).__init__(*args, **kwargs)

    def clean(self, value):
        # Any STIX Object (SDO, SRO, or Marking Definition) can be added to
        # a bundle with no further checks.
        if any(x in ('STIXDomainObject', 'STIXRelationshipObject', 'MarkingDefinition')
               for x in get_class_hierarchy_names(value)):
            # A simple "is this a spec version 2.1+ object" test.  For now,
            # limit 2.0 bundles to 2.0 objects.  It's not possible yet to
            # have validation co-constraints among properties, e.g. have
            # validation here depend on the value of another property
            # (spec_version).  So this is a hack, and not technically spec-
            # compliant.
            if "spec_version" in value:
                raise ValueError("Spec version 2.0 bundles don't yet support "
                                 "containing objects of a different spec "
                                 "version.")
            return value
        try:
            dictified = _get_dict(value)
        except ValueError:
            raise ValueError("This property may only contain a dictionary or object")
        if dictified == {}:
            raise ValueError("This property may only contain a non-empty dictionary or object")
        if 'type' in dictified and dictified['type'] == 'bundle':
            raise ValueError('This property may not contain a Bundle object')
        if "spec_version" in dictified:
            # See above comment regarding spec_version.
            raise ValueError("Spec version 2.0 bundles don't yet support "
                             "containing objects of a different spec version.")

        parsed_obj = parse(dictified, allow_custom=self.allow_custom)

        return parsed_obj


class Bundle(_STIXBase):
    """For more detailed information on this object's properties, see
    `the STIX 2.0 specification <http://docs.oasis-open.org/cti/stix/v2.0/cs01/part1-stix-core/stix-v2.0-cs01-part1-stix-core.html#_Toc496709293>`__.
    """

    _type = 'bundle'
    _properties = OrderedDict()
    _properties.update([
        ('type', TypeProperty(_type)),
        ('id', IDProperty(_type)),
        # Not technically correct: STIX 2.0 spec doesn't say spec_version must
        # have this value, but it's all we support for now.
        ('spec_version', StringProperty(fixed="2.0")),
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
