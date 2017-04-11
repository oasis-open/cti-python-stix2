import re
import uuid
from six import PY2
import datetime as dt
import pytz
from dateutil import parser


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
        - a `validate()` function that checks if the value matches the fixed
          value, and
        - a `default()` function that returns the fixed value.
        (Default: `None`)

    Subclasses can also define the following functions.

    - `def clean(self, value) -> any:`
        - Transform `value` into a valid value for this property. This should
          raise a ValueError if such no such transformation is possible.
    - `def validate(self, value) -> any:`
        - check that `value` is valid for this property. This should return
          a valid value (possibly modified) for this property, or raise a
          ValueError if the value is not valid.
          (Default: if `clean` is defined, it will attempt to call `clean` and
          return the result or pass on a ValueError that `clean` raises. If
          `clean` is not defined, this will return `value` unmodified).
    - `def default(self):`
        - provide a default value for this property.
        - `default()` can return the special value `NOW` to use the current
            time. This is useful when several timestamps in the same object need
            to use the same default value, so calling now() for each field--
            likely several microseconds apart-- does not work.

    Subclasses can instead provide lambda functions for `clean`, and `default`
    as keyword arguments. `validate` should not be provided as a lambda since
    lambdas cannot raise their own exceptions.
    """

    def _default_validate(self, value):
        if value != self._fixed_value:
            raise ValueError("must equal '{0}'.".format(self._fixed_value))
        return value

    def __init__(self, required=False, fixed=None, clean=None, default=None):
        self.required = required
        if fixed:
            self._fixed_value = fixed
            self.validate = self._default_validate
            self.default = lambda: fixed
        if clean:
            self.clean = clean
        if default:
            self.default = default

    def clean(self, value):
        raise NotImplementedError

    def validate(self, value):
        try:
            value = self.clean(value)
        except NotImplementedError:
            pass
        return value


class ListProperty(Property):

    def __init__(self, contained, **kwargs):
        """
        contained should be a type whose constructor creates an object from the value
        """
        if contained == StringProperty:
            self.contained = StringProperty().string_type
        elif contained == BooleanProperty:
            self.contained = bool
        else:
            self.contained = contained
        super(ListProperty, self).__init__(**kwargs)

    def validate(self, value):
        try:
            list_ = self.clean(value)
        except ValueError:
            raise

        # STIX spec forbids empty lists
        if len(list_) < 1:
            raise ValueError("must not be empty.")

        try:
            for item in list_:
                self.contained.validate(item)
        except ValueError:
            raise
        except AttributeError:
            # type of list has no validate() function (eg. built in Python types)
            # TODO Should we raise an error here?
            pass

        return list_

    def clean(self, value):
        try:
            iter(value)
        except TypeError:
            raise ValueError("must be an iterable.")

        try:
            return [self.contained(**x) if type(x) is dict else self.contained(x) for x in value]
        except TypeError:
            raise ValueError("the type of objects in the list must have a constructor that creates an object from the value.")


class StringProperty(Property):

    def __init__(self, **kwargs):
        if PY2:
            self.string_type = unicode
        else:
            self.string_type = str
        super(StringProperty, self).__init__(**kwargs)

    def clean(self, value):
        return self.string_type(value)

    def validate(self, value):
        try:
            val = self.clean(value)
        except ValueError:
            raise
        return val


class TypeProperty(Property):

    def __init__(self, type):
        super(TypeProperty, self).__init__(fixed=type)


class IDProperty(Property):

    def __init__(self, type):
        self.required_prefix = type + "--"
        super(IDProperty, self).__init__()

    def validate(self, value):
        if not value.startswith(self.required_prefix):
            raise ValueError("must start with '{0}'.".format(self.required_prefix))
        try:
            uuid.UUID(value.split('--', 1)[1], version=4)
        except Exception:
            raise ValueError("must have a valid version 4 UUID after the prefix.")
        return value

    def default(self):
        return self.required_prefix + str(uuid.uuid4())


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

        raise ValueError("not a coercible boolean value.")

    def validate(self, value):
        try:
            return self.clean(value)
        except ValueError:
            raise ValueError("must be a boolean value.")


class TimestampProperty(Property):

    def validate(self, value):
        if isinstance(value, dt.datetime):
            return value
        elif isinstance(value, dt.date):
            return dt.datetime.combine(value, dt.time())

        try:
            return parser.parse(value).astimezone(pytz.utc)
        except ValueError:
            # Doesn't have timezone info in the string
            try:
                return pytz.utc.localize(parser.parse(value))
            except TypeError:
                # Unknown format
                raise ValueError("must be a datetime object, date object, or "
                                 "timestamp string in a recognizable format.")
        except TypeError:
            # Isn't a string
            raise ValueError("must be a datetime object, date object, or "
                             "timestamp string.")


REF_REGEX = re.compile("^[a-z][a-z-]+[a-z]--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}"
                       "-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


class ReferenceProperty(Property):
    # TODO: support references that must be to a specific object type

    def validate(self, value):
        if not REF_REGEX.match(value):
            raise ValueError("must match <object-type>--<guid>.")
        return value
