"""STIX 2 Common Data Types and Properties"""

import re
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

ref_regex = ("^[a-z][a-z-]+[a-z]--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
             "-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

REF_PROPERTY = {
    'validate': (lambda x, val: re.match(ref_regex, val)),
    'error_msg': "{type} {field} values must consist of a valid STIX type name and a valid UUID, separated by '--'."
}

BOOL_PROPERTY = {
    'validate': (lambda x, val: isinstance(val, bool)),
    'error_msg': "{type} {field} value must be a boolean."
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
    'external_references': {},
    'revoked': BOOL_PROPERTY,
    'created_by_ref': REF_PROPERTY
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


class KillChainPhase(_STIXBase):
    _properties = {
        'kill_chain_name': {
            'required': True,
        },
        'phase_name': {
            'required': True,
        },
    }
