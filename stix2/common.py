"""STIX 2 Common Data Types and Properties"""

from .base import _STIXBase
from .utils import NOW

TYPE_PROPERTY = {
    'default': (lambda x: x._type),
    'validate': (lambda x, val: val == x._type)
}

ID_PROPERTY = {
    'default': (lambda x: x._make_id()),
    'validate': (lambda x, val: val.startswith(x._type + "--")),
    'expected': (lambda x: x._type + "--"),
    'error_msg': "{type} {field} values must begin with '{expected}'."
}

COMMON_PROPERTIES = {
    'type': TYPE_PROPERTY,
    'id': ID_PROPERTY,
    'created': {
        'default': NOW,
    },
    'modified': {
        'default': NOW,
    },
}


class ExternalReference(_STIXBase):
    _properties = {
        'source_name': {
            'required': True,
        },
        'description': {},
        'url': {},
        'external_id': {},
    }
