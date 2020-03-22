"""Base classes for STIX 2.1 type definitions."""

from ..base import _Extension, _Observable, _STIXBase
from ..core import STIXDomainObject, STIXRelationshipObject


class _STIXBase21(_STIXBase):
    _spec_version = "2.1"


class _Observable(_Observable, _STIXBase21):
    pass


class _Extension(_Extension, _STIXBase21):
    pass


class STIXDomainObject(STIXDomainObject, _STIXBase21):
    pass


class STIXRelationshipObject(STIXRelationshipObject, _STIXBase21):
    pass
