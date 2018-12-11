"""STIX 2.1 Bundle Representation."""

from collections import OrderedDict

from ..base import _STIXBase
from ..properties import (
    IDProperty, ListProperty, STIXObjectProperty, TypeProperty,
)


class Bundle(_STIXBase):
    # TODO: Add link
    """For more detailed information on this object's properties, see
    `the STIX 2.1 specification <link here>`__.
    """

    _type = 'bundle'
    _properties = OrderedDict([
        ('type', TypeProperty(_type)),
        ('id', IDProperty(_type)),
        ('objects', ListProperty(STIXObjectProperty(spec_version='2.1'))),
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
