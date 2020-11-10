"""Base classes for STIX 2.1 type definitions."""

from ..base import (
    _DomainObject, _Extension, _Observable, _RelationshipObject, _STIXBase,
)


class _STIXBase21(_STIXBase):

    def __init__(self, **kwargs):
        if 'extensions' in self._properties:
            self._properties['extensions'].allow_custom = kwargs.get('allow_custom', False)
        super(_STIXBase21, self).__init__(**kwargs)


class _Observable(_Observable, _STIXBase21):

    def __init__(self, **kwargs):
        super(_Observable, self).__init__(**kwargs)
        if 'id' not in kwargs:
            # Specific to 2.1+ observables: generate a deterministic ID
            id_ = self._generate_id()

            # Spec says fall back to UUIDv4 if no contributing properties were
            # given.  That's what already happened (the following is actually
            # overwriting the default uuidv4), so nothing to do here.
            if id_ is not None:
                # Can't assign to self (we're immutable), so slip the ID in
                # more sneakily.
                self._inner["id"] = id_


class _Extension(_Extension, _STIXBase21):
    extends_stix_object_definition = False
    is_new_object = False
    is_extension_so = False

    def __init__(self, **kwargs):
        super(_Extension, self).__init__(**kwargs)
        if getattr(self, "extends_stix_object_definition", False):
            self._inner["extends_stix_object_definition"] = True
        elif getattr(self, "is_new_object", False):
            self._inner["is_new_object"] = True
        elif getattr(self, "is_extension_so", False):
            self._inner["is_extension_so"] = True

    def _check_at_least_one_property(self, list_of_properties=None):
        new_ext_check = (getattr(self, "extends_stix_object_definition", False) or
                         getattr(self, "is_new_object", False) or
                         getattr(self, "is_extension_so", False))

        if new_ext_check is False:
            super(_Extension, self)._check_at_least_one_property(list_of_properties=list_of_properties)


class _DomainObject(_DomainObject, _STIXBase21):
    pass


class _RelationshipObject(_RelationshipObject, _STIXBase21):
    pass
