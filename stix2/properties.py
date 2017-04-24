import re
import uuid
from six import text_type
import datetime as dt
import pytz
from dateutil import parser
import inspect
import collections
from .base import _STIXBase


class Property(object):
    """Represent a property of STIX data type.

    Subclasses can define the following attributes as keyword arguments to
    __init__():

    - `required` - If `True`, the property must be provided when creating an
        object with that property. No default value exists for these properties.
        (Default: `False`)
    - `fixed` - This provides a constant default value. Users are free to
        provide this value explicity when constructing an object (which allows
        you to copy *all* values from an existing object to a new object), but
        if the user provides a value other than the `fixed` value, it will raise
        an error. This is semantically equivalent to defining both:
        - a `clean()` function that checks if the value matches the fixed
          value, and
        - a `default()` function that returns the fixed value.
        (Default: `None`)

    Subclasses can also define the following functions.

    - `def clean(self, value) -> any:`
        - Return a value that is valid for this property. If `value` is not
          valid for this property, this will attempt to transform it first. If
          `value` is not valid and no such transformation is possible, it should
          raise a ValueError.
    - `def default(self):`
        - provide a default value for this property.
        - `default()` can return the special value `NOW` to use the current
            time. This is useful when several timestamps in the same object need
            to use the same default value, so calling now() for each field--
            likely several microseconds apart-- does not work.

    Subclasses can instead provide a lambda function for `default` as a keyword
    argument. `clean` should not be provided as a lambda since lambdas cannot
    raise their own exceptions.

    When instantiating Properties, `required` and `default` should not be used
    together. `default` implies that the field is required in the specification
    so this function will be used to supply a value if none is provided.
    `required` means that the user must provide this; it is required in the
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
        Contained should be a function which returns an object from the value.
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

            if isinstance(valid, collections.Mapping):
                result.append(self.contained(**valid))
            else:
                result.append(self.contained(valid))

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
            uuid.UUID(value.split('--', 1)[1], version=4)
        except Exception:
            raise ValueError("must have a valid version 4 UUID after the prefix.")
        return value

    def default(self):
        return self.required_prefix + str(uuid.uuid4())


class IntegerProperty(Property):

    def clean(self, value):
        try:
            return int(value)
        except Exception:
            raise ValueError("must be an integer.")


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

    def clean(self, value):
        if isinstance(value, dt.date):
            if hasattr(value, 'hour'):
                return value
            else:
                # Add a time component
                return dt.datetime.combine(value, dt.time(), tzinfo=pytz.utc)

        # value isn't a date or datetime object so assume it's a string
        try:
            parsed = parser.parse(value)
        except TypeError:
            # Unknown format
            raise ValueError("must be a datetime object, date object, or "
                             "timestamp string in a recognizable format.")
        if parsed.tzinfo:
            return parsed.astimezone(pytz.utc)
        else:
            # Doesn't have timezone info in the string; assume UTC
            return pytz.utc.localize(parsed)


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
