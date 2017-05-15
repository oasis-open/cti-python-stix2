"""STIX 2 Common Data Types and Properties"""

from .other import ExternalReference, GranularMarking
from .properties import (BooleanProperty, ListProperty, ReferenceProperty,
                         StringProperty, TimestampProperty)
from .utils import NOW

COMMON_PROPERTIES = {
    # 'type' and 'id' should be defined on each individual type
    'created': TimestampProperty(default=lambda: NOW),
    'modified': TimestampProperty(default=lambda: NOW),
    'external_references': ListProperty(ExternalReference),
    'revoked': BooleanProperty(),
    'labels': ListProperty(StringProperty),
    'created_by_ref': ReferenceProperty(type="identity"),
    'object_marking_refs': ListProperty(ReferenceProperty(type="marking-definition")),
    'granular_markings': ListProperty(GranularMarking),
}
