"""STIX2 Error Classes."""


class STIXError(Exception):
    """Base class for errors generated in the stix2 library."""


class InvalidValueError(STIXError, ValueError):
    """An invalid value was provided to a STIX object's ``__init__``."""

    def __init__(self, cls, prop_name, reason):
        super(InvalidValueError, self).__init__()
        self.cls = cls
        self.prop_name = prop_name
        self.reason = reason

    def __str__(self):
        msg = "Invalid value for {0.cls.__name__} '{0.prop_name}': {0.reason}"
        return msg.format(self)


class MissingPropertiesError(STIXError, ValueError):
    """Missing one or more required properties when constructing STIX object."""

    def __init__(self, cls, properties):
        super(MissingPropertiesError, self).__init__()
        self.cls = cls
        self.properties = sorted(list(properties))

    def __str__(self):
        msg = "No values for required properties for {0}: ({1})."
        return msg.format(
            self.cls.__name__,
            ", ".join(x for x in self.properties),
        )


class ExtraPropertiesError(STIXError, TypeError):
    """One or more extra properties were provided when constructing STIX object."""

    def __init__(self, cls, properties):
        super(ExtraPropertiesError, self).__init__()
        self.cls = cls
        self.properties = sorted(list(properties))

    def __str__(self):
        msg = "Unexpected properties for {0}: ({1})."
        return msg.format(
            self.cls.__name__,
            ", ".join(x for x in self.properties),
        )


class ImmutableError(STIXError, ValueError):
    """Attempted to modify an object after creation."""

    def __init__(self, cls, key):
        super(ImmutableError, self).__init__()
        self.cls = cls
        self.key = key

    def __str__(self):
        msg = "Cannot modify '{0.key}' property in '{0.cls.__name__}' after creation."
        return msg.format(self)


class DictionaryKeyError(STIXError, ValueError):
    """Dictionary key does not conform to the correct format."""

    def __init__(self, key, reason):
        super(DictionaryKeyError, self).__init__()
        self.key = key
        self.reason = reason

    def __str__(self):
        msg = "Invalid dictionary key {0.key}: ({0.reason})."
        return msg.format(self)


class InvalidObjRefError(STIXError, ValueError):
    """A STIX Cyber Observable Object contains an invalid object reference."""

    def __init__(self, cls, prop_name, reason):
        super(InvalidObjRefError, self).__init__()
        self.cls = cls
        self.prop_name = prop_name
        self.reason = reason

    def __str__(self):
        msg = "Invalid object reference for '{0.cls.__name__}:{0.prop_name}': {0.reason}"
        return msg.format(self)


class UnmodifiablePropertyError(STIXError, ValueError):
    """Attempted to modify an unmodifiable property of object when creating a new version."""

    def __init__(self, unchangable_properties):
        super(UnmodifiablePropertyError, self).__init__()
        self.unchangable_properties = unchangable_properties

    def __str__(self):
        msg = "These properties cannot be changed when making a new version: {0}."
        return msg.format(", ".join(self.unchangable_properties))


class MutuallyExclusivePropertiesError(STIXError, TypeError):
    """Violating interproperty mutually exclusive constraint of a STIX object type."""

    def __init__(self, cls, properties):
        super(MutuallyExclusivePropertiesError, self).__init__()
        self.cls = cls
        self.properties = sorted(list(properties))

    def __str__(self):
        msg = "The ({1}) properties for {0} are mutually exclusive."
        return msg.format(
            self.cls.__name__,
            ", ".join(x for x in self.properties),
        )


class DependentPropertiesError(STIXError, TypeError):
    """Violating interproperty dependency constraint of a STIX object type."""

    def __init__(self, cls, dependencies):
        super(DependentPropertiesError, self).__init__()
        self.cls = cls
        self.dependencies = dependencies

    def __str__(self):
        msg = "The property dependencies for {0}: ({1}) are not met."
        return msg.format(
            self.cls.__name__,
            ", ".join(name for x in self.dependencies for name in x),
        )


class AtLeastOnePropertyError(STIXError, TypeError):
    """Violating a constraint of a STIX object type that at least one of the given properties must be populated."""

    def __init__(self, cls, properties):
        super(AtLeastOnePropertyError, self).__init__()
        self.cls = cls
        self.properties = sorted(list(properties))

    def __str__(self):
        msg = "At least one of the ({1}) properties for {0} must be populated."
        return msg.format(
            self.cls.__name__,
            ", ".join(x for x in self.properties),
        )


class RevokeError(STIXError, ValueError):
    """Attempted to an operation on a revoked object."""

    def __init__(self, called_by):
        super(RevokeError, self).__init__()
        self.called_by = called_by

    def __str__(self):
        if self.called_by == "revoke":
            return "Cannot revoke an already revoked object."
        else:
            return "Cannot create a new version of a revoked object."


class ParseError(STIXError, ValueError):
    """Could not parse object."""

    def __init__(self, msg):
        super(ParseError, self).__init__(msg)


class CustomContentError(STIXError, ValueError):
    """Custom STIX Content (SDO, Observable, Extension, etc.) detected."""

    def __init__(self, msg):
        super(CustomContentError, self).__init__(msg)


class InvalidSelectorError(STIXError, AssertionError):
    """Granular Marking selector violation. The selector must resolve into an existing STIX object property."""

    def __init__(self, cls, key):
        super(InvalidSelectorError, self).__init__()
        self.cls = cls
        self.key = key

    def __str__(self):
        msg = "Selector {0} in {1} is not valid!"
        return msg.format(self.key, self.cls.__class__.__name__)


class MarkingNotFoundError(STIXError, AssertionError):
    """Marking violation. The marking reference must be present in SDO or SRO."""

    def __init__(self, cls, key):
        super(MarkingNotFoundError, self).__init__()
        self.cls = cls
        self.key = key

    def __str__(self):
        msg = "Marking {0} was not found in {1}!"
        return msg.format(self.key, self.cls.__class__.__name__)
