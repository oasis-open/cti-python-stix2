"""Base classes for STIX 2.1 type definitions."""

from ..base import (
    _DomainObject, _Extension, _Observable, _RelationshipObject, _STIXBase,
)


class _STIXBase21(_STIXBase):
    pass


class _Observable(_Observable, _STIXBase21):
    pass


class _Extension(_Extension, _STIXBase21):
    pass


class _DomainObject(_DomainObject, _STIXBase21):
    pass


class _RelationshipObject(_RelationshipObject, _STIXBase21):
    pass
