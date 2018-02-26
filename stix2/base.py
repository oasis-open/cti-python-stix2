"""Base classes for type definitions in the stix2 library."""

import collections
import copy
import datetime as dt

import simplejson as json

from .exceptions import (AtLeastOnePropertyError, DependentPropertiesError,
                         ExtraPropertiesError, ImmutableError,
                         InvalidObjRefError, InvalidValueError,
                         MissingPropertiesError,
                         MutuallyExclusivePropertiesError)
from .markings.utils import validate
from .utils import NOW, find_property_index, format_datetime, get_timestamp
from .utils import new_version as _new_version
from .utils import revoke as _revoke

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

    def object_properties(self):
        props = set(self._properties.keys())
        custom_props = list(set(self._inner.keys()) - props)
        custom_props.sort()

        all_properties = list(self._properties.keys())
        all_properties.extend(custom_props)  # Any custom properties to the bottom

        return all_properties

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

    def _check_properties_dependency(self, list_of_properties, list_of_dependent_properties):
        failed_dependency_pairs = []
        for p in list_of_properties:
            for dp in list_of_dependent_properties:
                if not self.get(p) and self.get(dp):
                    failed_dependency_pairs.append((p, dp))
        if failed_dependency_pairs:
            raise DependentPropertiesError(self.__class__, failed_dependency_pairs)

    def _check_object_constraints(self):
        for m in self.get("granular_markings", []):
            validate(self, m.get("selectors"))

    def __init__(self, allow_custom=False, **kwargs):
        cls = self.__class__

        # Use the same timestamp for any auto-generated datetimes
        self.__now = get_timestamp()

        # Detect any keyword arguments not allowed for a specific type
        custom_props = kwargs.pop('custom_properties', {})
        if custom_props and not isinstance(custom_props, dict):
            raise ValueError("'custom_properties' must be a dictionary")
        if not allow_custom:
            extra_kwargs = list(set(kwargs) - set(cls._properties))
            if extra_kwargs:
                raise ExtraPropertiesError(cls, extra_kwargs)

        # Remove any keyword arguments whose value is None
        setting_kwargs = {}
        props = kwargs.copy()
        props.update(custom_props)
        for prop_name, prop_value in props.items():
            if prop_value is not None:
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
        if name in self:
            return self.__getitem__(name)
        raise AttributeError("'%s' object has no attribute '%s'" %
                             (self.__class__.__name__, name))

    def __setattr__(self, name, value):
        if name != '_inner' and not name.startswith("_STIXBase__"):
            raise ImmutableError(self.__class__, name)
        super(_STIXBase, self).__setattr__(name, value)

    def __str__(self):
        return self.serialize(pretty=True)

    def __repr__(self):
        props = [(k, self[k]) for k in self.object_properties() if self.get(k)]
        return "{0}({1})".format(self.__class__.__name__,
                                 ", ".join(["{0!s}={1!r}".format(k, v) for k, v in props]))

    def __deepcopy__(self, memo):
        # Assume: we can ignore the memo argument, because no object will ever contain the same sub-object multiple times.
        new_inner = copy.deepcopy(self._inner, memo)
        cls = type(self)
        if isinstance(self, _Observable):
            # Assume: valid references in the original object are still valid in the new version
            new_inner['_valid_refs'] = {'*': '*'}
        return cls(**new_inner)

    def properties_populated(self):
        return list(self._inner.keys())

#  Versioning API

    def new_version(self, **kwargs):
        return _new_version(self, **kwargs)

    def revoke(self):
        return _revoke(self)

    def serialize(self, pretty=False, **kwargs):
        """
        Serialize a STIX object.

        Args:
            pretty (bool): If True, output properties following the STIX specs
                formatting. This includes indentation. Refer to notes for more
                details.
            **kwargs: The arguments for a json.dumps() call.

        Returns:
            dict: The serialized JSON object.

        Note:
            The argument ``pretty=True`` will output the STIX object following
            spec order. Using this argument greatly impacts object serialization
            performance. If your use case is centered across machine-to-machine
            operation it is recommended to set ``pretty=False``.

            When ``pretty=True`` the following key-value pairs will be added or
            overridden: indent=4, separators=(",", ": "), item_sort_key=sort_by.
        """
        if pretty:
            properties = self.object_properties()

            def sort_by(element):
                return find_property_index(self, properties, element)

            kwargs.update({'indent': 4, 'separators': (",", ": "), 'item_sort_key': sort_by})

        return json.dumps(self, cls=STIXJSONEncoder, **kwargs)


class _Observable(_STIXBase):

    def __init__(self, **kwargs):
        # the constructor might be called independently of an observed data object
        if '_valid_refs' in kwargs:
            self._STIXBase__valid_refs = kwargs.pop('_valid_refs')
        else:
            self._STIXBase__valid_refs = []
        super(_Observable, self).__init__(**kwargs)

    def _check_ref(self, ref, prop, prop_name):
        if '*' in self._STIXBase__valid_refs:
            return  # don't check if refs are valid

        if ref not in self._STIXBase__valid_refs:
            raise InvalidObjRefError(self.__class__, prop_name, "'%s' is not a valid object in local scope" % ref)

        try:
            allowed_types = prop.contained.valid_types
        except AttributeError:
            allowed_types = prop.valid_types

        try:
            ref_type = self._STIXBase__valid_refs[ref]
        except TypeError:
            raise ValueError("'%s' must be created with _valid_refs as a dict, not a list." % self.__class__.__name__)

        if allowed_types:
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
