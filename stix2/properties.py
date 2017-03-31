import re
import uuid
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

    def __init__(self, required=False, fixed=None, clean=None, default=None, type=None):
        self.required = required
        self.type = type
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

    def __init__(self, contained, required=False, element_type=None):
        """
        contained should be a type whose constructor creates an object from the value
        """
        self.contained = contained
        self.element_type = element_type
        super(ListProperty, self).__init__(required)

    def validate(self, value):
        # TODO: ensure iterable
        result = []
        for item in value:
            result.append(self.contained(type=self.element_type).validate(item))
        return result

    def clean(self, value):
        return [self.contained(x) for x in value]


class TypeProperty(Property):
    def __init__(self, type):
        super(TypeProperty, self).__init__(fixed=type)


class IDProperty(Property):

    def __init__(self, type):
        self.required_prefix = type + "--"
        super(IDProperty, self).__init__()

    def validate(self, value):
        # TODO: validate GUID as well
        if not value.startswith(self.required_prefix):
            raise ValueError("must start with '{0}'.".format(self.required_prefix))
        return value

    def default(self):
        return self.required_prefix + str(uuid.uuid4())


class BooleanProperty(Property):
    # TODO:  Consider coercing some values (like the strings "true" and "false")

    def validate(self, value):
        if not isinstance(value, bool):
            raise ValueError("must be a boolean value.")
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

    def validate(self, value):
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

    def validate(self, value):
        if not SELECTOR_REGEX.match(value):
            raise ValueError("values must adhere to selector syntax")
        return value
