"""Classes for representing properties of STIX Objects and Cyber Observables.
"""
import base64
import binascii
import collections
import inspect
import re
import uuid

from six import string_types, text_type
from stix2patterns.validator import run_validator

from .base import _STIXBase
from .exceptions import DictionaryKeyError
from .utils import get_dict, parse_into_datetime


class Property(object):
    """Represent a property of STIX data type.

    Subclasses can define the following attributes as keyword arguments to
    ``__init__()``.

    Args:
        required (bool): If ``True``, the property must be provided when creating an
            object with that property. No default value exists for these properties.
            (Default: ``False``)
        fixed: This provides a constant default value. Users are free to
            provide this value explicity when constructing an object (which allows
            you to copy **all** values from an existing object to a new object), but
            if the user provides a value other than the ``fixed`` value, it will raise
            an error. This is semantically equivalent to defining both:

            - a ``clean()`` function that checks if the value matches the fixed
              value, and
            - a ``default()`` function that returns the fixed value.

    Subclasses can also define the following functions:

    - ``def clean(self, value) -> any:``
        - Return a value that is valid for this property. If ``value`` is not
          valid for this property, this will attempt to transform it first. If
          ``value`` is not valid and no such transformation is possible, it should
          raise a ValueError.
    - ``def default(self):``
        - provide a default value for this property.
        - ``default()`` can return the special value ``NOW`` to use the current
            time. This is useful when several timestamps in the same object need
            to use the same default value, so calling now() for each property--
            likely several microseconds apart-- does not work.

    Subclasses can instead provide a lambda function for ``default`` as a keyword
    argument. ``clean`` should not be provided as a lambda since lambdas cannot
    raise their own exceptions.

    When instantiating Properties, ``required`` and ``default`` should not be used
    together. ``default`` implies that the property is required in the specification
    so this function will be used to supply a value if none is provided.
    ``required`` means that the user must provide this; it is required in the
    specification and we can't or don't want to create a default value.
    """

    def _default_clean(self, value):
        if value != self._fixed_value:
            raise ValueError("must equal '{0}'.".format(self._fixed_value))
        return value

    def __init__(self, required=False, fixed=None, default=None, type=None):
        self.required = required
        self.type = type
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
            elif type(self.contained).__name__ is 'STIXObjectProperty':
                # ^ this way of checking doesn't require a circular import
                # valid is already an instance of a python-stix2 class; no need
                # to turn it into a dictionary and then pass it to the class
                # constructor again
                result.append(valid)
                continue
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
            raise ValueError("must start with '{0}'.".format(self.required_prefix))
        try:
            uuid.UUID(value.split('--', 1)[1])
        except Exception:
            raise ValueError("must have a valid UUID after the prefix.")
        return value

    def default(self):
        return self.required_prefix + str(uuid.uuid4())


class IntegerProperty(Property):

    def clean(self, value):
        try:
            return int(value)
        except Exception:
            raise ValueError("must be an integer.")


class FloatProperty(Property):
    def clean(self, value):
        try:
            return float(value)
        except Exception:
            raise ValueError("must be a float.")


class BooleanProperty(Property):

    def clean(self, value):
        if isinstance(value, bool):
            return value

        trues = ['true', 't']
        falses = ['false', 'f']
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

    def clean(self, value):
        try:
            dictified = get_dict(value)
        except ValueError:
            raise ValueError("The dictionary property must contain a dictionary")
        if dictified == {}:
            raise ValueError("The dictionary property must contain a non-empty dictionary")

        for k in dictified.keys():
            if len(k) < 3:
                raise DictionaryKeyError(k, "shorter than 3 characters")
            elif len(k) > 256:
                raise DictionaryKeyError(k, "longer than 256 characters")
            if not re.match('^[a-zA-Z0-9_-]+$', k):
                raise DictionaryKeyError(k, "contains characters other than"
                                         "lowercase a-z, uppercase A-Z, "
                                         "numerals 0-9, hyphen (-), or "
                                         "underscore (_)")
        return dictified


HASHES_REGEX = {
    "MD5": ("^[a-fA-F0-9]{32}$", "MD5"),
    "MD6": ("^[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{56}|[a-fA-F0-9]{64}|[a-fA-F0-9]{96}|[a-fA-F0-9]{128}$", "MD6"),
    "RIPEMD160": ("^[a-fA-F0-9]{40}$", "RIPEMD-160"),
    "SHA1": ("^[a-fA-F0-9]{40}$", "SHA-1"),
    "SHA224": ("^[a-fA-F0-9]{56}$", "SHA-224"),
    "SHA256": ("^[a-fA-F0-9]{64}$", "SHA-256"),
    "SHA384": ("^[a-fA-F0-9]{96}$", "SHA-384"),
    "SHA512": ("^[a-fA-F0-9]{128}$", "SHA-512"),
    "SHA3224": ("^[a-fA-F0-9]{56}$", "SHA3-224"),
    "SHA3256": ("^[a-fA-F0-9]{64}$", "SHA3-256"),
    "SHA3384": ("^[a-fA-F0-9]{96}$", "SHA3-384"),
    "SHA3512": ("^[a-fA-F0-9]{128}$", "SHA3-512"),
    "SSDEEP": ("^[a-zA-Z0-9/+:.]{1,128}$", "ssdeep"),
    "WHIRLPOOL": ("^[a-fA-F0-9]{128}$", "WHIRLPOOL"),
}


class HashesProperty(DictionaryProperty):

    def clean(self, value):
        clean_dict = super(HashesProperty, self).clean(value)
        for k, v in clean_dict.items():
            key = k.upper().replace('-', '')
            if key in HASHES_REGEX:
                vocab_key = HASHES_REGEX[key][1]
                if not re.match(HASHES_REGEX[key][0], v):
                    raise ValueError("'%s' is not a valid %s hash" % (v, vocab_key))
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
        if not re.match('^([a-fA-F0-9]{2})+$', value):
            raise ValueError("must contain an even number of hexadecimal characters")
        return value


REF_REGEX = re.compile("^[a-z][a-z-]+[a-z]--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}"
                       "-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


class ReferenceProperty(Property):

    def __init__(self, required=False, type=None):
        """
        references sometimes must be to a specific object type
        """
        self.type = type
        super(ReferenceProperty, self).__init__(required, type=type)

    def clean(self, value):
        if isinstance(value, _STIXBase):
            value = value.id
        value = str(value)
        if self.type:
            if not value.startswith(self.type):
                raise ValueError("must start with '{0}'.".format(self.type))
        if not REF_REGEX.match(value):
            raise ValueError("must match <object-type>--<guid>.")
        return value


SELECTOR_REGEX = re.compile("^[a-z0-9_-]{3,250}(\\.(\\[\\d+\\]|[a-z0-9_-]{1,250}))*$")


class SelectorProperty(Property):

    def __init__(self, type=None):
        # ignore type
        super(SelectorProperty, self).__init__()

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

    def __init__(self, type, required=False):
        self.type = type
        super(EmbeddedObjectProperty, self).__init__(required, type=type)

    def clean(self, value):
        if type(value) is dict:
            value = self.type(**value)
        elif not isinstance(value, self.type):
            raise ValueError("must be of type %s." % self.type.__name__)
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
            raise ValueError("value '%s' is not valid for this enumeration." % value)
        return self.string_type(value)


class PatternProperty(StringProperty):

    def __init__(self, **kwargs):
        super(PatternProperty, self).__init__(**kwargs)

    def clean(self, value):
        str_value = super(PatternProperty, self).clean(value)
        errors = run_validator(str_value)
        if errors:
            raise ValueError(str(errors[0]))

        return self.string_type(value)
