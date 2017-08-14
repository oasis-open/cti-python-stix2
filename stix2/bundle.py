"""STIX 2 Bundle object"""

from collections import OrderedDict

from .base import _STIXBase
from .properties import IDProperty, Property, TypeProperty


class Bundle(_STIXBase):

    _type = 'bundle'
    _properties = OrderedDict()
    _properties = _properties.update([
        ('type', TypeProperty(_type)),
        ('id', IDProperty(_type)),
        ('spec_version', Property(fixed="2.0")),
        ('objects', Property()),
    ])

    def __init__(self, *args, **kwargs):
        # Add any positional arguments to the 'objects' kwarg.
        if args:
            if isinstance(args[0], list):
                kwargs['objects'] = args[0] + list(args[1:]) + kwargs.get('objects', [])
            else:
                kwargs['objects'] = list(args) + kwargs.get('objects', [])

        super(Bundle, self).__init__(**kwargs)
