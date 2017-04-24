"""STIX 2 Bundle object"""

from .base import _STIXBase
from .properties import IDProperty, Property, TypeProperty


class Bundle(_STIXBase):

    _type = 'bundle'
    _properties = {
        'type': TypeProperty(_type),
        'id': IDProperty(_type),
        'spec_version': Property(fixed="2.0"),
        'objects': Property(),
    }

    def __init__(self, *args, **kwargs):
        # Add any positional arguments to the 'objects' kwarg.
        if args:
            kwargs['objects'] = kwargs.get('objects', []) + list(args)

        super(Bundle, self).__init__(**kwargs)
