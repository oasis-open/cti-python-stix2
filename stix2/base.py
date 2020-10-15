"""Base classes for type definitions in the STIX2 library."""

import copy
import re
import uuid

import simplejson as json
import six

import stix2
from stix2.canonicalization.Canonicalize import canonicalize

from .exceptions import (
    AtLeastOnePropertyError, DependentPropertiesError, ExtraPropertiesError,
    ImmutableError, InvalidObjRefError, InvalidValueError,
    MissingPropertiesError, MutuallyExclusivePropertiesError,
)
from .markings import _MarkingsMixin
from .markings.utils import validate
from .serialization import (
    STIXJSONEncoder, STIXJSONIncludeOptionalDefaultsEncoder, serialize,
)
from .utils import NOW, PREFIX_21_REGEX, get_timestamp
from .versioning import new_version as _new_version
from .versioning import revoke as _revoke

try:
    from collections.abc import Mapping
except ImportError:
    from collections import Mapping

# TODO: Remove STIXJSONEncoder, STIXJSONIncludeOptionalDefaultsEncoder, serialize from __all__ on next major release.
# Kept for backwards compatibility.
__all__ = ['STIXJSONEncoder', 'STIXJSONIncludeOptionalDefaultsEncoder', '_STIXBase', 'serialize']

DEFAULT_ERROR = "{type} must have {property}='{expected}'."
SCO_DET_ID_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")


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

        extra_kwargs = list(set(kwargs) - set(self._properties))
        if extra_kwargs and not self._allow_custom:
            raise ExtraPropertiesError(cls, extra_kwargs)

        # because allow_custom is true, any extra kwargs are custom
        if custom_props or extra_kwargs:
            self._allow_custom = True
            if isinstance(self, stix2.v21._STIXBase21):
                all_custom_prop_names = extra_kwargs
                all_custom_prop_names.extend(list(custom_props.keys()))
                for prop_name in all_custom_prop_names:
                    if not re.match(PREFIX_21_REGEX, prop_name):
                        raise InvalidValueError(
                            self.__class__, prop_name,
                            reason="Property name '%s' must begin with an alpha character." % prop_name,
                        )

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

    def serialize(self, *args, **kwargs):
        """
        Serialize a STIX object.

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

        See Also:
            ``stix2.serialization.serialize`` for options.
        """
        return serialize(self, *args, **kwargs)


class _DomainObject(_STIXBase, _MarkingsMixin):
    pass


class _RelationshipObject(_STIXBase, _MarkingsMixin):
    pass


class _Observable(_STIXBase):

    def __init__(self, **kwargs):
        # the constructor might be called independently of an observed data object
        self._STIXBase__valid_refs = kwargs.pop('_valid_refs', [])
        self._properties['extensions'].allow_custom = kwargs.get('allow_custom', False)
        super(_Observable, self).__init__(**kwargs)

        if 'id' not in kwargs and not isinstance(self, stix2.v20._Observable):
            # Specific to 2.1+ observables: generate a deterministic ID
            id_ = self._generate_id()

            # Spec says fall back to UUIDv4 if no contributing properties were
            # given.  That's what already happened (the following is actually
            # overwriting the default uuidv4), so nothing to do here.
            if id_ is not None:
                # Can't assign to self (we're immutable), so slip the ID in
                # more sneakily.
                self._inner["id"] = id_

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

    def _generate_id(self):
        """
        Generate a UUIDv5 for this observable, using its "ID contributing
        properties".

        :return: The ID, or None if no ID contributing properties are set
        """

        id_ = None
        json_serializable_object = {}

        for key in self._id_contributing_properties:

            if key in self:
                obj_value = self[key]

                if key == "hashes":
                    serializable_value = _choose_one_hash(obj_value)

                    if serializable_value is None:
                        raise InvalidValueError(
                            self, key, "No hashes given",
                        )

                else:
                    serializable_value = _make_json_serializable(obj_value)

                json_serializable_object[key] = serializable_value

        if json_serializable_object:

            data = canonicalize(json_serializable_object, utf8=False)

            # The situation is complicated w.r.t. python 2/3 behavior, so
            # I'd rather not rely on particular exceptions being raised to
            # determine what to do.  Better to just check the python version
            # directly.
            if six.PY3:
                uuid_ = uuid.uuid5(SCO_DET_ID_NAMESPACE, data)
            else:
                uuid_ = uuid.uuid5(
                    SCO_DET_ID_NAMESPACE, data.encode("utf-8"),
                )

            id_ = "{}--{}".format(self._type, six.text_type(uuid_))

        return id_


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

    return None


def _cls_init(cls, obj, kwargs):
    if getattr(cls, '__init__', object.__init__) is not object.__init__:
        cls.__init__(obj, **kwargs)


def _make_json_serializable(value):
    """
    Make the given value JSON-serializable; required for the JSON canonicalizer
    to work.  This recurses into lists/dicts, converts stix objects to dicts,
    etc.  "Convenience" types this library uses as property values are
    JSON-serialized to produce a JSON-serializable value.  (So you will always
    get strings for those.)

    The conversion will not affect the passed in value.

    :param value: The value to make JSON-serializable.
    :return: The JSON-serializable value.
    :raises ValueError: If value is None (since nulls are not allowed in STIX
        objects).
    """
    if value is None:
        raise ValueError("Illegal null value found in a STIX object")

    json_value = value  # default assumption

    if isinstance(value, Mapping):
        json_value = {
            k: _make_json_serializable(v)
            for k, v in value.items()
        }

    elif isinstance(value, list):
        json_value = [
            _make_json_serializable(v)
            for v in value
        ]

    elif not isinstance(value, (int, float, six.string_types, bool)):
        # If a "simple" value which is not already JSON-serializable,
        # JSON-serialize to a string and use that as our JSON-serializable
        # value.  This applies to our datetime objects currently (timestamp
        # properties), and could apply to any other "convenience" types this
        # library uses for property values in the future.
        json_value = json.dumps(value, ensure_ascii=False, cls=STIXJSONEncoder)

        # If it looks like a string literal was output, strip off the quotes.
        # Otherwise, a second pair will be added when it's canonicalized.  Also
        # to be extra safe, we need to unescape.
        if len(json_value) >= 2 and \
                json_value[0] == '"' and json_value[-1] == '"':
            json_value = _un_json_escape(json_value[1:-1])

    return json_value


_JSON_ESCAPE_RE = re.compile(r"\\.")
# I don't think I should need to worry about the unicode escapes (\uXXXX)
# since I use ensure_ascii=False when generating it.  I will just fix all
# the other escapes, e.g. \n, \r, etc.
#
# This list is taken from RFC8259 section 7:
# https://tools.ietf.org/html/rfc8259#section-7
# Maps the second char of a "\X" style escape, to a replacement char
_JSON_ESCAPE_MAP = {
    '"': '"',
    "\\": "\\",
    "/": "/",
    "b": "\b",
    "f": "\f",
    "n": "\n",
    "r": "\r",
    "t": "\t",
}


def _un_json_escape(json_string):
    """
    Removes JSON string literal escapes.  We should undo these things Python's
    serializer does, so we can ensure they're done canonically.  The
    canonicalizer should be in charge of everything, as much as is feasible.

    :param json_string: String literal output of Python's JSON serializer,
        minus the surrounding quotes.
    :return: The unescaped string
    """

    def replace(m):
        replacement = _JSON_ESCAPE_MAP.get(m.group(0)[1])
        if replacement is None:
            raise ValueError("Unrecognized JSON escape: " + m.group(0))

        return replacement

    result = _JSON_ESCAPE_RE.sub(replace, json_string)

    return result
