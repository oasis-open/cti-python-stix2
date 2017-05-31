"""Base class for type definitions in the stix2 library."""

import collections
import copy
import datetime as dt
import json

from .exceptions import (AtLeastOnePropertyError, DependentPropertiesError, ExtraPropertiesError, ImmutableError,
                         InvalidObjRefError, InvalidValueError, MissingPropertiesError, MutuallyExclusivePropertiesError,
                         RevokeError, UnmodifiablePropertyError)
from .utils import NOW, format_datetime, get_timestamp, parse_into_datetime

__all__ = ['STIXJSONEncoder', '_STIXBase']

DEFAULT_ERROR = "{type} must have {property}='{expected}'."


class STIXJSONEncoder(json.JSONEncoder):

    def default(self, obj):
        if isinstance(obj, (dt.date, dt.datetime)):
            return format_datetime(obj)
        elif isinstance(obj, _STIXBase):
            return dict(obj)
        else:
            return super(STIXJSONEncoder, self).default(obj)


def get_required_properties(properties):
    return (k for k, v in properties.items() if v.required)


class _STIXBase(collections.Mapping):
    """Base class for STIX object types"""

    def _check_property(self, prop_name, prop, kwargs):
        if prop_name not in kwargs:
            if hasattr(prop, 'default'):
                value = prop.default()
                if value == NOW:
                    value = self.__now
                kwargs[prop_name] = value

        if prop_name in kwargs:
            try:
                kwargs[prop_name] = prop.clean(kwargs[prop_name])
            except ValueError as exc:
                raise InvalidValueError(self.__class__, prop_name, reason=str(exc))

    # interproperty constraint methods

    def _check_mutually_exclusive_properties(self, list_of_properties, at_least_one=True):
        current_properties = self.properties_populated()
        count = len(set(list_of_properties).intersection(current_properties))
        # at_least_one allows for xor to be checked
        if count > 1 or (at_least_one and count == 0):
            raise MutuallyExclusivePropertiesError(self.__class__, list_of_properties)

    def _check_at_least_one_property(self, list_of_properties=None):
        if not list_of_properties:
            list_of_properties = sorted(list(self.__class__._properties.keys()))
            if "type" in list_of_properties:
                list_of_properties.remove("type")
        current_properties = self.properties_populated()
        list_of_properties_populated = set(list_of_properties).intersection(current_properties)
        if list_of_properties and (not list_of_properties_populated or list_of_properties_populated == set(["extensions"])):
            raise AtLeastOnePropertyError(self.__class__, list_of_properties)

    def _check_properties_dependency(self, list_of_properties, list_of_dependent_properties, values=[]):
        failed_dependency_pairs = []
        current_properties = self.properties_populated()
        for p in list_of_properties:
            v = values.pop() if values else None
            for dp in list_of_dependent_properties:
                if dp in current_properties and (p not in current_properties or (v and not current_properties(p) == v)):
                    failed_dependency_pairs.append((p, dp))
        if failed_dependency_pairs:
            raise DependentPropertiesError(self.__class__, failed_dependency_pairs)

    def _check_object_constraints(self):
        if self.granular_markings:
            for m in self.granular_markings:
                # TODO: check selectors
                pass

    def __init__(self, **kwargs):
        cls = self.__class__

        # Use the same timestamp for any auto-generated datetimes
        self.__now = get_timestamp()

        # Detect any keyword arguments not allowed for a specific type
        extra_kwargs = list(set(kwargs) - set(cls._properties))
        if extra_kwargs:
            raise ExtraPropertiesError(cls, extra_kwargs)

        # Remove any keyword arguments whose value is None
        setting_kwargs = {}
        for prop_name, prop_value in kwargs.items():
            if prop_value:
                setting_kwargs[prop_name] = prop_value

        # Detect any missing required properties
        required_properties = get_required_properties(cls._properties)
        missing_kwargs = set(required_properties) - set(setting_kwargs)
        if missing_kwargs:
            raise MissingPropertiesError(cls, missing_kwargs)

        for prop_name, prop_metadata in cls._properties.items():
            self._check_property(prop_name, prop_metadata, setting_kwargs)

        self._inner = setting_kwargs

        self._check_object_constraints()

    def __getitem__(self, key):
        return self._inner[key]

    def __iter__(self):
        return iter(self._inner)

    def __len__(self):
        return len(self._inner)

    # Handle attribute access just like key access
    def __getattr__(self, name):
        return self.get(name)

    def __setattr__(self, name, value):
        if name != '_inner' and not name.startswith("_STIXBase__"):
            raise ImmutableError
        super(_STIXBase, self).__setattr__(name, value)

    def __str__(self):
        # TODO: put keys in specific order. Probably need custom JSON encoder.
        return json.dumps(self, indent=4, sort_keys=True, cls=STIXJSONEncoder,
                          separators=(",", ": "))  # Don't include spaces after commas.

    def __repr__(self):
        props = [(k, self[k]) for k in sorted(self._properties) if self.get(k)]
        return "{0}({1})".format(self.__class__.__name__,
                                 ", ".join(["{0!s}={1!r}".format(k, v) for k, v in props]))

    def __deepcopy__(self, memo):
        # Assumption: we can ignore the memo argument, because no object will ever contain the same sub-object multiple times.
        new_inner = copy.deepcopy(self._inner, memo)
        cls = type(self)
        return cls(**new_inner)

    def properties_populated(self):
        return list(self._inner.keys())

#  Versioning API

    def new_version(self, **kwargs):
        unchangable_properties = []
        if self.revoked:
            raise RevokeError("new_version")
        new_obj_inner = copy.deepcopy(self._inner)
        properties_to_change = kwargs.keys()
        for prop in ["created", "created_by_ref", "id", "type"]:
            if prop in properties_to_change:
                unchangable_properties.append(prop)
        if unchangable_properties:
            raise UnmodifiablePropertyError(unchangable_properties)
        cls = type(self)
        if 'modified' not in kwargs:
            kwargs['modified'] = get_timestamp()
        else:
            new_modified_property = parse_into_datetime(kwargs['modified'])
            if new_modified_property < self.modified:
                raise InvalidValueError(cls, 'modified', "The new modified datetime cannot be before the current modified datatime.")
        new_obj_inner.update(kwargs)
        return cls(**new_obj_inner)

    def revoke(self):
        if self.revoked:
            raise RevokeError("revoke")
        return self.new_version(revoked=True)


class _Observable(_STIXBase):

    def __init__(self, **kwargs):
        # the constructor might be called independently of an observed data object
        if '_valid_refs' in kwargs:
            self._STIXBase__valid_refs = kwargs.pop('_valid_refs')
        else:
            self._STIXBase__valid_refs = []
        super(_Observable, self).__init__(**kwargs)

    def _check_ref(self, ref, prop, prop_name):
        if ref not in self._STIXBase__valid_refs:
            raise InvalidObjRefError(self.__class__, prop_name, "'%s' is not a valid object in local scope" % ref)

        try:
            allowed_types = prop.contained.valid_types
        except AttributeError:
            try:
                allowed_types = prop.valid_types
            except AttributeError:
                raise ValueError("'%s' is named like an object reference property but "
                                 "is not an ObjectReferenceProperty or a ListProperty "
                                 "containing ObjectReferenceProperty." % prop_name)

        if allowed_types:
            try:
                ref_type = self._STIXBase__valid_refs[ref]
            except TypeError:
                raise ValueError("'%s' must be created with _valid_refs as a dict, not a list." % self.__class__.__name__)
            if ref_type not in allowed_types:
                raise InvalidObjRefError(self.__class__, prop_name, "object reference '%s' is of an invalid type '%s'" % (ref, ref_type))

    def _check_property(self, prop_name, prop, kwargs):
        super(_Observable, self)._check_property(prop_name, prop, kwargs)
        if prop_name not in kwargs:
            return

        if prop_name.endswith('_ref'):
            ref = kwargs[prop_name]
            self._check_ref(ref, prop, prop_name)
        elif prop_name.endswith('_refs'):
            for ref in kwargs[prop_name]:
                self._check_ref(ref, prop, prop_name)


class _Extension(_STIXBase):

    def _check_object_constraints(self):
        super(_Extension, self)._check_object_constraints()
        self._check_at_least_one_property()
