"""Base classes for type definitions in the STIX2 library."""

import copy
import datetime as dt
import uuid

import simplejson as json
import six

from stix2.canonicalization.Canonicalize import canonicalize

from .exceptions import (
    AtLeastOnePropertyError, DependentPropertiesError, ExtraPropertiesError,
    ImmutableError, InvalidObjRefError, InvalidValueError,
    MissingPropertiesError, MutuallyExclusivePropertiesError,
)
from .markings.utils import validate
from .utils import NOW, find_property_index, format_datetime, get_timestamp
from .utils import new_version as _new_version
from .utils import revoke as _revoke

try:
    from collections.abc import Mapping
except ImportError:
    from collections import Mapping


__all__ = ['STIXJSONEncoder', '_STIXBase']

DEFAULT_ERROR = "{type} must have {property}='{expected}'."
SCO_DET_ID_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")


class STIXJSONEncoder(json.JSONEncoder):
    """Custom JSONEncoder subclass for serializing Python ``stix2`` objects.

    If an optional property with a default value specified in the STIX 2 spec
    is set to that default value, it will be left out of the serialized output.

    An example of this type of property include the ``revoked`` common property.
    """

    def default(self, obj):
        if isinstance(obj, (dt.date, dt.datetime)):
            return format_datetime(obj)
        elif isinstance(obj, _STIXBase):
            tmp_obj = dict(copy.deepcopy(obj))
            for prop_name in obj._defaulted_optional_properties:
                del tmp_obj[prop_name]
            return tmp_obj
        else:
            return super(STIXJSONEncoder, self).default(obj)


class STIXJSONIncludeOptionalDefaultsEncoder(json.JSONEncoder):
    """Custom JSONEncoder subclass for serializing Python ``stix2`` objects.

    Differs from ``STIXJSONEncoder`` in that if an optional property with a default
    value specified in the STIX 2 spec is set to that default value, it will be
    included in the serialized output.
    """

    def default(self, obj):
        if isinstance(obj, (dt.date, dt.datetime)):
            return format_datetime(obj)
        elif isinstance(obj, _STIXBase):
            return dict(obj)
        else:
            return super(STIXJSONIncludeOptionalDefaultsEncoder, self).default(obj)


def get_required_properties(properties):
    return (k for k, v in properties.items() if v.required)


class _STIXBase(Mapping):
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
            except InvalidValueError:
                # No point in wrapping InvalidValueError in another
                # InvalidValueError... so let those propagate.
                raise
            except Exception as exc:
                six.raise_from(
                    InvalidValueError(
                        self.__class__, prop_name, reason=str(exc),
                    ),
                    exc,
                )

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
            if isinstance(self, _Observable):
                props_to_remove = ["type", "id", "defanged", "spec_version"]
            else:
                props_to_remove = ["type"]

            list_of_properties = [prop for prop in list_of_properties if prop not in props_to_remove]
        current_properties = self.properties_populated()
        list_of_properties_populated = set(list_of_properties).intersection(current_properties)

        if list_of_properties and (not list_of_properties_populated or list_of_properties_populated == set(['extensions'])):
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
        for m in self.get('granular_markings', []):
            validate(self, m.get('selectors'))

    def __init__(self, allow_custom=False, **kwargs):
        cls = self.__class__
        self._allow_custom = allow_custom

        # Use the same timestamp for any auto-generated datetimes
        self.__now = get_timestamp()

        # Detect any keyword arguments not allowed for a specific type
        custom_props = kwargs.pop('custom_properties', {})
        if custom_props and not isinstance(custom_props, dict):
            raise ValueError("'custom_properties' must be a dictionary")
        if not self._allow_custom:
            extra_kwargs = list(set(kwargs) - set(self._properties))
            if extra_kwargs:
                raise ExtraPropertiesError(cls, extra_kwargs)
        if custom_props:
            self._allow_custom = True

        # Remove any keyword arguments whose value is None or [] (i.e. empty list)
        setting_kwargs = {}
        props = kwargs.copy()
        props.update(custom_props)
        for prop_name, prop_value in props.items():
            if prop_value is not None and prop_value != []:
                setting_kwargs[prop_name] = prop_value

        # Detect any missing required properties
        required_properties = set(get_required_properties(self._properties))
        missing_kwargs = required_properties - set(setting_kwargs)
        if missing_kwargs:
            raise MissingPropertiesError(cls, missing_kwargs)

        for prop_name, prop_metadata in self._properties.items():
            self._check_property(prop_name, prop_metadata, setting_kwargs)

        # Cache defaulted optional properties for serialization
        defaulted = []
        for name, prop in self._properties.items():
            try:
                if (not prop.required and not hasattr(prop, '_fixed_value') and
                        prop.default() == setting_kwargs[name]):
                    defaulted.append(name)
            except (AttributeError, KeyError):
                continue
        self._defaulted_optional_properties = defaulted

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
        # Pickle-proofing: pickle invokes this on uninitialized instances (i.e.
        # __init__ has not run).  So no "self" attributes are set yet.  The
        # usual behavior of this method reads an __init__-assigned attribute,
        # which would cause infinite recursion.  So this check disables all
        # attribute reads until the instance has been properly initialized.
        unpickling = '_inner' not in self.__dict__
        if not unpickling and name in self:
            return self.__getitem__(name)
        raise AttributeError("'%s' object has no attribute '%s'" %
                             (self.__class__.__name__, name))

    def __setattr__(self, name, value):
        if not name.startswith("_"):
            raise ImmutableError(self.__class__, name)
        super(_STIXBase, self).__setattr__(name, value)

    def __str__(self):
        return self.serialize(pretty=True)

    def __repr__(self):
        props = [(k, self[k]) for k in self.object_properties() if self.get(k)]
        return '{0}({1})'.format(
            self.__class__.__name__,
            ', '.join(['{0!s}={1!r}'.format(k, v) for k, v in props]),
        )

    def __deepcopy__(self, memo):
        # Assume: we can ignore the memo argument, because no object will ever contain the same sub-object multiple times.
        new_inner = copy.deepcopy(self._inner, memo)
        cls = type(self)
        if isinstance(self, _Observable):
            # Assume: valid references in the original object are still valid in the new version
            new_inner['_valid_refs'] = {'*': '*'}
        new_inner['allow_custom'] = self._allow_custom
        return cls(**new_inner)

    def properties_populated(self):
        return list(self._inner.keys())

#  Versioning API

    def new_version(self, **kwargs):
        return _new_version(self, **kwargs)

    def revoke(self):
        return _revoke(self)

    def serialize(self, pretty=False, include_optional_defaults=False, **kwargs):
        """
        Serialize a STIX object.

        Args:
            pretty (bool): If True, output properties following the STIX specs
                formatting. This includes indentation. Refer to notes for more
                details. (Default: ``False``)
            include_optional_defaults (bool): Determines whether to include
                optional properties set to the default value defined in the spec.
            **kwargs: The arguments for a json.dumps() call.

        Examples:
            >>> import stix2
            >>> identity = stix2.Identity(name='Example Corp.', identity_class='organization')
            >>> print(identity.serialize(sort_keys=True))
            {"created": "2018-06-08T19:03:54.066Z", ... "name": "Example Corp.", "type": "identity"}
            >>> print(identity.serialize(sort_keys=True, indent=4))
            {
                "created": "2018-06-08T19:03:54.066Z",
                "id": "identity--d7f3e25a-ba1c-447a-ab71-6434b092b05e",
                "identity_class": "organization",
                "modified": "2018-06-08T19:03:54.066Z",
                "name": "Example Corp.",
                "type": "identity"
            }

        Returns:
            str: The serialized JSON object.

        Note:
            The argument ``pretty=True`` will output the STIX object following
            spec order. Using this argument greatly impacts object serialization
            performance. If your use case is centered across machine-to-machine
            operation it is recommended to set ``pretty=False``.

            When ``pretty=True`` the following key-value pairs will be added or
            overridden: indent=4, separators=(",", ": "), item_sort_key=sort_by.
        """
        if pretty:
            def sort_by(element):
                return find_property_index(self, *element)

            kwargs.update({'indent': 4, 'separators': (',', ': '), 'item_sort_key': sort_by})

        if include_optional_defaults:
            return json.dumps(self, cls=STIXJSONIncludeOptionalDefaultsEncoder, **kwargs)
        else:
            return json.dumps(self, cls=STIXJSONEncoder, **kwargs)


class _Observable(_STIXBase):

    def __init__(self, **kwargs):
        # the constructor might be called independently of an observed data object
        self._STIXBase__valid_refs = kwargs.pop('_valid_refs', [])

        self._allow_custom = kwargs.get('allow_custom', False)
        self._properties['extensions'].allow_custom = kwargs.get('allow_custom', False)

        try:
            # Since `spec_version` is optional, this is how we check for a 2.1 SCO
            self._id_contributing_properties

            if 'id' not in kwargs:
                possible_id = self._generate_id(kwargs)
                if possible_id is not None:
                    kwargs['id'] = possible_id
        except AttributeError:
            # End up here if handling a 2.0 SCO, and don't need to do anything further
            pass

        super(_Observable, self).__init__(**kwargs)

    def _check_ref(self, ref, prop, prop_name):
        """
        Only for checking `*_ref` or `*_refs` properties in spec_version 2.0
        STIX Cyber Observables (SCOs)
        """

        if '*' in self._STIXBase__valid_refs:
            return  # don't check if refs are valid

        if ref not in self._STIXBase__valid_refs:
            raise InvalidObjRefError(self.__class__, prop_name, "'%s' is not a valid object in local scope" % ref)

        try:
            allowed_types = prop.contained.valid_types
        except AttributeError:
            allowed_types = prop.valid_types

        try:
            try:
                ref_type = self._STIXBase__valid_refs[ref].type
            except AttributeError:
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

        from .properties import ObjectReferenceProperty
        if prop_name.endswith('_ref'):
            if isinstance(prop, ObjectReferenceProperty):
                ref = kwargs[prop_name]
                self._check_ref(ref, prop, prop_name)
        elif prop_name.endswith('_refs'):
            if isinstance(prop.contained, ObjectReferenceProperty):
                for ref in kwargs[prop_name]:
                    self._check_ref(ref, prop, prop_name)

    def _generate_id(self, kwargs):
        required_prefix = self._type + "--"

        properties_to_use = self._id_contributing_properties
        if properties_to_use:
            streamlined_obj_vals = []
            if "hashes" in kwargs and "hashes" in properties_to_use:
                possible_hash = _choose_one_hash(kwargs["hashes"])
                if possible_hash:
                    streamlined_obj_vals.append(possible_hash)
            for key in properties_to_use:
                if key != "hashes" and key in kwargs:
                    if isinstance(kwargs[key], dict) or isinstance(kwargs[key], _STIXBase):
                        temp_deep_copy = copy.deepcopy(dict(kwargs[key]))
                        _recursive_stix_to_dict(temp_deep_copy)
                        streamlined_obj_vals.append(temp_deep_copy)
                    elif isinstance(kwargs[key], list) and isinstance(kwargs[key][0], _STIXBase):
                        for obj in kwargs[key]:
                            temp_deep_copy = copy.deepcopy(dict(obj))
                            _recursive_stix_to_dict(temp_deep_copy)
                            streamlined_obj_vals.append(temp_deep_copy)
                    else:
                        streamlined_obj_vals.append(kwargs[key])

            if streamlined_obj_vals:
                data = canonicalize(streamlined_obj_vals, utf8=False)

                # The situation is complicated w.r.t. python 2/3 behavior, so
                # I'd rather not rely on particular exceptions being raised to
                # determine what to do.  Better to just check the python version
                # directly.
                if six.PY3:
                    return required_prefix + six.text_type(uuid.uuid5(SCO_DET_ID_NAMESPACE, data))
                else:
                    return required_prefix + six.text_type(uuid.uuid5(SCO_DET_ID_NAMESPACE, data.encode("utf-8")))

        # We return None if there are no values specified for any of the id-contributing-properties
        return None


class _Extension(_STIXBase):

    def _check_object_constraints(self):
        super(_Extension, self)._check_object_constraints()
        self._check_at_least_one_property()


def _choose_one_hash(hash_dict):
    if "MD5" in hash_dict:
        return {"MD5": hash_dict["MD5"]}
    elif "SHA-1" in hash_dict:
        return {"SHA-1": hash_dict["SHA-1"]}
    elif "SHA-256" in hash_dict:
        return {"SHA-256": hash_dict["SHA-256"]}
    elif "SHA-512" in hash_dict:
        return {"SHA-512": hash_dict["SHA-512"]}
    else:
        k = next(iter(hash_dict), None)
        if k is not None:
            return {k: hash_dict[k]}


def _cls_init(cls, obj, kwargs):
    if getattr(cls, '__init__', object.__init__) is not object.__init__:
        cls.__init__(obj, **kwargs)


def _recursive_stix_to_dict(input_dict):
    for key in input_dict:
        if isinstance(input_dict[key], dict):
            _recursive_stix_to_dict(input_dict[key])
        elif isinstance(input_dict[key], _STIXBase):
            input_dict[key] = dict(input_dict[key])

            # There may stil be nested _STIXBase objects
            _recursive_stix_to_dict(input_dict[key])
        else:
            return
