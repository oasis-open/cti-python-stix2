"""STIX 2 Common Data Types and Properties"""

import re

from .base import _STIXBase
from .properties import Property, BooleanProperty, ReferenceProperty
from .utils import NOW

COMMON_PROPERTIES = {
    # 'type' and 'id' should be defined on each individual type
    'created': {
        'default': NOW,
    },
    'modified': {
        'default': NOW,
    },
    'external_references': {},
    'revoked': BooleanProperty(),
    'created_by_ref': ReferenceProperty(),
}


class ExternalReference(_STIXBase):
    _properties = {
        'source_name': Property(required=True),
        'description': Property(),
        'url': Property(),
        'external_id': Property(),
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
