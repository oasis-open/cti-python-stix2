"""Classes for representing properties of STIX Objects and Cyber Observables."""

import base64
import binascii
import collections
import copy
import inspect
import re
import uuid

from six import string_types, text_type
from stix2patterns.validator import run_validator

from .base import _Observable, _STIXBase
from .core import STIX2_OBJ_MAPS, parse, parse_observable
from .exceptions import CustomContentError, DictionaryKeyError
from .utils import _get_dict, get_class_hierarchy_names, parse_into_datetime

# This uses the regular expression for a RFC 4122, Version 4 UUID. In the
# 8-4-4-4-12 hexadecimal representation, the first hex digit of the third
# component must be a 4, and the first hex digit of the fourth component
# must be 8, 9, a, or b (10xx bit pattern).
ID_REGEX = re.compile(
    r"^[a-z0-9][a-z0-9-]+[a-z0-9]--"  # object type
    "[0-9a-fA-F]{8}-"
    "[0-9a-fA-F]{4}-"
    "4[0-9a-fA-F]{3}-"
    "[89abAB][0-9a-fA-F]{3}-"
    "[0-9a-fA-F]{12}$",
)

ERROR_INVALID_ID = (
    "not a valid STIX identifier, must match <object-type>--<UUIDv4>"
)


class Property(object):
    """Represent a property of STIX data type.

    Subclasses can define the following attributes as keyword arguments to
    ``__init__()``.

    Args:
        required (bool): If ``True``, the property must be provided when
            creating an object with that property. No default value exists for
            these properties. (Default: ``False``)
        fixed: This provides a constant default value. Users are free to
            provide this value explicity when constructing an object (which
            allows you to copy **all** values from an existing object to a new
            object), but if the user provides a value other than the ``fixed``
            value, it will raise an error. This is semantically equivalent to
            defining both:

            - a ``clean()`` function that checks if the value matches the fixed
              value, and
            - a ``default()`` function that returns the fixed value.

    Subclasses can also define the following functions:

    - ``def clean(self, value) -> any:``
        - Return a value that is valid for this property. If ``value`` is not
          valid for this property, this will attempt to transform it first. If
          ``value`` is not valid and no such transformation is possible, it
          should raise a ValueError.
    - ``def default(self):``
        - provide a default value for this property.
        - ``default()`` can return the special value ``NOW`` to use the current
            time. This is useful when several timestamps in the same object
            need to use the same default value, so calling now() for each
            property-- likely several microseconds apart-- does not work.

    Subclasses can instead provide a lambda function for ``default`` as a
    keyword argument. ``clean`` should not be provided as a lambda since
    lambdas cannot raise their own exceptions.

    When instantiating Properties, ``required`` and ``default`` should not be
    used together. ``default`` implies that the property is required in the
    specification so this function will be used to supply a value if none is
    provided. ``required`` means that the user must provide this; it is
    required in the specification and we can't or don't want to create a
    default value.

    """

    def _default_clean(self, value):
        if value != self._fixed_value:
            raise ValueError("must equal '{}'.".format(self._fixed_value))
        return value

    def __init__(self, required=False, fixed=None, default=None):
        self.required = required
        if fixed:
            self._fixed_value = fixed
            self.clean = self._default_clean
            self.default = lambda: fixed
        if default:
            self.default = default

    def clean(self, value):
        return value

    def __call__(self, value=None):
        """Used by ListProperty to handle lists that have been defined with
        either a class or an instance.
        """
        return value


class ListProperty(Property):

    def __init__(self, contained, **kwargs):
        """
        ``contained`` should be a function which returns an object from the value.
        """
        if inspect.isclass(contained) and issubclass(contained, Property):
            # If it's a class and not an instance, instantiate it so that
            # clean() can be called on it, and ListProperty.clean() will
            # use __call__ when it appends the item.
            self.contained = contained()
        else:
            self.contained = contained
        super(ListProperty, self).__init__(**kwargs)

    def clean(self, value):
        try:
            iter(value)
        except TypeError:
            raise ValueError("must be an iterable.")

        if isinstance(value, (_STIXBase, string_types)):
            value = [value]

        result = []
        for item in value:
            try:
                valid = self.contained.clean(item)
            except ValueError:
                raise
            except AttributeError:
                # type of list has no clean() function (eg. built in Python types)
                # TODO Should we raise an error here?
                valid = item

            if type(self.contained) is EmbeddedObjectProperty:
                obj_type = self.contained.type
            elif type(self.contained).__name__ == "STIXObjectProperty":
                # ^ this way of checking doesn't require a circular import
                # valid is already an instance of a python-stix2 class; no need
                # to turn it into a dictionary and then pass it to the class
                # constructor again
                result.append(valid)
                continue
            elif type(self.contained) is DictionaryProperty:
                obj_type = dict
            else:
                obj_type = self.contained

            if isinstance(valid, collections.Mapping):
                result.append(obj_type(**valid))
            else:
                result.append(obj_type(valid))

        # STIX spec forbids empty lists
        if len(result) < 1:
            raise ValueError("must not be empty.")

        return result


class CallableValues(list):
    """Wrapper to allow `values()` method on WindowsRegistryKey objects.
    Needed because `values` is also a property.
    """

    def __init__(self, parent_instance, *args, **kwargs):
        self.parent_instance = parent_instance
        super(CallableValues, self).__init__(*args, **kwargs)

    def __call__(self):
        return _Observable.values(self.parent_instance)


class StringProperty(Property):

    def __init__(self, **kwargs):
        self.string_type = text_type
        super(StringProperty, self).__init__(**kwargs)

    def clean(self, value):
        return self.string_type(value)


class TypeProperty(Property):

    def __init__(self, type):
        super(TypeProperty, self).__init__(fixed=type)


class IDProperty(Property):

    def __init__(self, type):
        self.required_prefix = type + "--"
        super(IDProperty, self).__init__()

    def clean(self, value):
        if not value.startswith(self.required_prefix):
            raise ValueError("must start with '{}'.".format(self.required_prefix))
        if not ID_REGEX.match(value):
            raise ValueError(ERROR_INVALID_ID)
        return value

    def default(self):
        return self.required_prefix + str(uuid.uuid4())


class IntegerProperty(Property):

    def __init__(self, min=None, max=None, **kwargs):
        self.min = min
        self.max = max
        super(IntegerProperty, self).__init__(**kwargs)

    def clean(self, value):
        try:
            value = int(value)
        except Exception:
            raise ValueError("must be an integer.")

        if self.min is not None and value < self.min:
            msg = "minimum value is {}. received {}".format(self.min, value)
            raise ValueError(msg)

        if self.max is not None and value > self.max:
            msg = "maximum value is {}. received {}".format(self.max, value)
            raise ValueError(msg)

        return value


class FloatProperty(Property):

    def __init__(self, min=None, max=None, **kwargs):
        self.min = min
        self.max = max
        super(FloatProperty, self).__init__(**kwargs)

    def clean(self, value):
        try:
            value = float(value)
        except Exception:
            raise ValueError("must be a float.")

        if self.min is not None and value < self.min:
            msg = "minimum value is {}. received {}".format(self.min, value)
            raise ValueError(msg)

        if self.max is not None and value > self.max:
            msg = "maximum value is {}. received {}".format(self.max, value)
            raise ValueError(msg)

        return value


class BooleanProperty(Property):

    def clean(self, value):
        if isinstance(value, bool):
            return value

        trues = ['true', 't', '1']
        falses = ['false', 'f', '0']
        try:
            if value.lower() in trues:
                return True
            if value.lower() in falses:
                return False
        except AttributeError:
            if value == 1:
                return True
            if value == 0:
                return False

        raise ValueError("must be a boolean value.")


class TimestampProperty(Property):

    def __init__(self, precision=None, **kwargs):
        self.precision = precision
        super(TimestampProperty, self).__init__(**kwargs)

    def clean(self, value):
        return parse_into_datetime(value, self.precision)


class DictionaryProperty(Property):

    def __init__(self, spec_version='2.0', **kwargs):
        self.spec_version = spec_version
        super(DictionaryProperty, self).__init__(**kwargs)

    def clean(self, value):
        try:
            dictified = _get_dict(value)
        except ValueError:
            raise ValueError("The dictionary property must contain a dictionary")
        for k in dictified.keys():
            if self.spec_version == '2.0':
                if len(k) < 3:
                    raise DictionaryKeyError(k, "shorter than 3 characters")
                elif len(k) > 256:
                    raise DictionaryKeyError(k, "longer than 256 characters")
            elif self.spec_version == '2.1':
                if len(k) > 250:
                    raise DictionaryKeyError(k, "longer than 250 characters")
            if not re.match(r"^[a-zA-Z0-9_-]+$", k):
                msg = (
                    "contains characters other than lowercase a-z, "
                    "uppercase A-Z, numerals 0-9, hyphen (-), or "
                    "underscore (_)"
                )
                raise DictionaryKeyError(k, msg)
        return dictified


HASHES_REGEX = {
    "MD5": (r"^[a-fA-F0-9]{32}$", "MD5"),
    "MD6": (r"^[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{56}|[a-fA-F0-9]{64}|[a-fA-F0-9]{96}|[a-fA-F0-9]{128}$", "MD6"),
    "RIPEMD160": (r"^[a-fA-F0-9]{40}$", "RIPEMD-160"),
    "SHA1": (r"^[a-fA-F0-9]{40}$", "SHA-1"),
    "SHA224": (r"^[a-fA-F0-9]{56}$", "SHA-224"),
    "SHA256": (r"^[a-fA-F0-9]{64}$", "SHA-256"),
    "SHA384": (r"^[a-fA-F0-9]{96}$", "SHA-384"),
    "SHA512": (r"^[a-fA-F0-9]{128}$", "SHA-512"),
    "SHA3224": (r"^[a-fA-F0-9]{56}$", "SHA3-224"),
    "SHA3256": (r"^[a-fA-F0-9]{64}$", "SHA3-256"),
    "SHA3384": (r"^[a-fA-F0-9]{96}$", "SHA3-384"),
    "SHA3512": (r"^[a-fA-F0-9]{128}$", "SHA3-512"),
    "SSDEEP": (r"^[a-zA-Z0-9/+:.]{1,128}$", "ssdeep"),
    "WHIRLPOOL": (r"^[a-fA-F0-9]{128}$", "WHIRLPOOL"),
}


class HashesProperty(DictionaryProperty):

    def clean(self, value):
        clean_dict = super(HashesProperty, self).clean(value)
        for k, v in clean_dict.items():
            key = k.upper().replace('-', '')
            if key in HASHES_REGEX:
                vocab_key = HASHES_REGEX[key][1]
                if not re.match(HASHES_REGEX[key][0], v):
                    raise ValueError("'{0}' is not a valid {1} hash".format(v, vocab_key))
                if k != vocab_key:
                    clean_dict[vocab_key] = clean_dict[k]
                    del clean_dict[k]
        return clean_dict


class BinaryProperty(Property):

    def clean(self, value):
        try:
            base64.b64decode(value)
        except (binascii.Error, TypeError):
            raise ValueError("must contain a base64 encoded string")
        return value


class HexProperty(Property):

    def clean(self, value):
        if not re.match(r"^([a-fA-F0-9]{2})+$", value):
            raise ValueError("must contain an even number of hexadecimal characters")
        return value


class ReferenceProperty(Property):

    def __init__(self, type=None, **kwargs):
        """
        references sometimes must be to a specific object type
        """
        self.type = type
        super(ReferenceProperty, self).__init__(**kwargs)

    def clean(self, value):
        if isinstance(value, _STIXBase):
            value = value.id
        value = str(value)
        if self.type:
            if not value.startswith(self.type):
                raise ValueError("must start with '{}'.".format(self.type))
        if not ID_REGEX.match(value):
            raise ValueError(ERROR_INVALID_ID)
        return value


SELECTOR_REGEX = re.compile(r"^[a-z0-9_-]{3,250}(\.(\[\d+\]|[a-z0-9_-]{1,250}))*$")


class SelectorProperty(Property):

    def clean(self, value):
        if not SELECTOR_REGEX.match(value):
            raise ValueError("must adhere to selector syntax.")
        return value


class ObjectReferenceProperty(StringProperty):

    def __init__(self, valid_types=None, **kwargs):
        if valid_types and type(valid_types) is not list:
            valid_types = [valid_types]
        self.valid_types = valid_types
        super(ObjectReferenceProperty, self).__init__(**kwargs)


class EmbeddedObjectProperty(Property):

    def __init__(self, type, **kwargs):
        self.type = type
        super(EmbeddedObjectProperty, self).__init__(**kwargs)

    def clean(self, value):
        if type(value) is dict:
            value = self.type(**value)
        elif not isinstance(value, self.type):
            raise ValueError("must be of type {}.".format(self.type.__name__))
        return value


class EnumProperty(StringProperty):

    def __init__(self, allowed, **kwargs):
        if type(allowed) is not list:
            allowed = list(allowed)
        self.allowed = allowed
        super(EnumProperty, self).__init__(**kwargs)

    def clean(self, value):
        value = super(EnumProperty, self).clean(value)
        if value not in self.allowed:
            raise ValueError("value '{}' is not valid for this enumeration.".format(value))
        return self.string_type(value)


class PatternProperty(StringProperty):

    def clean(self, value):
        str_value = super(PatternProperty, self).clean(value)
        errors = run_validator(str_value)
        if errors:
            raise ValueError(str(errors[0]))

        return self.string_type(value)


class ObservableProperty(Property):
    """Property for holding Cyber Observable Objects.
    """

    def __init__(self, spec_version='2.0', allow_custom=False, *args, **kwargs):
        self.allow_custom = allow_custom
        self.spec_version = spec_version
        super(ObservableProperty, self).__init__(*args, **kwargs)

    def clean(self, value):
        try:
            dictified = _get_dict(value)
            # get deep copy since we are going modify the dict and might
            # modify the original dict as _get_dict() does not return new
            # dict when passed a dict
            dictified = copy.deepcopy(dictified)
        except ValueError:
            raise ValueError("The observable property must contain a dictionary")
        if dictified == {}:
            raise ValueError("The observable property must contain a non-empty dictionary")

        valid_refs = dict((k, v['type']) for (k, v) in dictified.items())

        for key, obj in dictified.items():
            parsed_obj = parse_observable(
                obj,
                valid_refs,
                allow_custom=self.allow_custom,
                version=self.spec_version,
            )
            dictified[key] = parsed_obj

        return dictified


class ExtensionsProperty(DictionaryProperty):
    """Property for representing extensions on Observable objects.
    """

    def __init__(self, spec_version='2.0', allow_custom=False, enclosing_type=None, required=False):
        self.allow_custom = allow_custom
        self.enclosing_type = enclosing_type
        super(ExtensionsProperty, self).__init__(spec_version=spec_version, required=required)

    def clean(self, value):
        try:
            dictified = _get_dict(value)
            # get deep copy since we are going modify the dict and might
            # modify the original dict as _get_dict() does not return new
            # dict when passed a dict
            dictified = copy.deepcopy(dictified)
        except ValueError:
            raise ValueError("The extensions property must contain a dictionary")

        v = 'v' + self.spec_version.replace('.', '')

        specific_type_map = STIX2_OBJ_MAPS[v]['observable-extensions'].get(self.enclosing_type, {})
        for key, subvalue in dictified.items():
            if key in specific_type_map:
                cls = specific_type_map[key]
                if type(subvalue) is dict:
                    if self.allow_custom:
                        subvalue['allow_custom'] = True
                        dictified[key] = cls(**subvalue)
                    else:
                        dictified[key] = cls(**subvalue)
                elif type(subvalue) is cls:
                    # If already an instance of an _Extension class, assume it's valid
                    dictified[key] = subvalue
                else:
                    raise ValueError("Cannot determine extension type.")
            else:
                raise CustomContentError("Can't parse unknown extension type: {}".format(key))
        return dictified


class STIXObjectProperty(Property):

    def __init__(self, spec_version='2.0', allow_custom=False, *args, **kwargs):
        self.allow_custom = allow_custom
        self.spec_version = spec_version
        super(STIXObjectProperty, self).__init__(*args, **kwargs)

    def clean(self, value):
        # Any STIX Object (SDO, SRO, or Marking Definition) can be added to
        # a bundle with no further checks.
        if any(x in ('STIXDomainObject', 'STIXRelationshipObject', 'MarkingDefinition')
               for x in get_class_hierarchy_names(value)):
            # A simple "is this a spec version 2.1+ object" test.  For now,
            # limit 2.0 bundles to 2.0 objects.  It's not possible yet to
            # have validation co-constraints among properties, e.g. have
            # validation here depend on the value of another property
            # (spec_version).  So this is a hack, and not technically spec-
            # compliant.
            if 'spec_version' in value and self.spec_version == '2.0':
                raise ValueError(
                    "Spec version 2.0 bundles don't yet support "
                    "containing objects of a different spec "
                    "version.",
                )
            return value
        try:
            dictified = _get_dict(value)
        except ValueError:
            raise ValueError("This property may only contain a dictionary or object")
        if dictified == {}:
            raise ValueError("This property may only contain a non-empty dictionary or object")
        if 'type' in dictified and dictified['type'] == 'bundle':
            raise ValueError("This property may not contain a Bundle object")
        if 'spec_version' in dictified and self.spec_version == '2.0':
            # See above comment regarding spec_version.
            raise ValueError(
                "Spec version 2.0 bundles don't yet support "
                "containing objects of a different spec version.",
            )

        parsed_obj = parse(dictified, allow_custom=self.allow_custom)

        return parsed_obj
