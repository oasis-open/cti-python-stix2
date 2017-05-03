class STIXError(Exception):
    """Base class for errors generated in the stix2 library."""


class InvalidValueError(STIXError, ValueError):
    """An invalid value was provided to a STIX object's __init__."""

    def __init__(self, cls, prop_name, reason):
        super(InvalidValueError, self).__init__()
        self.cls = cls
        self.prop_name = prop_name
        self.reason = reason

    def __str__(self):
        msg = "Invalid value for {0.cls.__name__} '{0.prop_name}': {0.reason}"
        return msg.format(self)


class MissingFieldsError(STIXError, ValueError):
    """Missing required field(s) when constructing STIX object."""

    def __init__(self, cls, fields):
        super(MissingFieldsError, self).__init__()
        self.cls = cls
        self.fields = sorted(list(fields))

    def __str__(self):
        msg = "Missing required field(s) for {0}: ({1})."
        return msg.format(self.cls.__name__,
                          ", ".join(x for x in self.fields))


class ExtraFieldsError(STIXError, TypeError):
    """Extra field(s) were provided when constructing STIX object."""

    def __init__(self, cls, fields):
        super(ExtraFieldsError, self).__init__()
        self.cls = cls
        self.fields = sorted(list(fields))

    def __str__(self):
        msg = "Unexpected field(s) for {0}: ({1})."
        return msg.format(self.cls.__name__,
                          ", ".join(x for x in self.fields))


class ImmutableError(STIXError, ValueError):
    """Attempted to modify an object after creation"""

    def __init__(self):
        super(ImmutableError, self).__init__("Cannot modify properties after creation.")


class UnmodifiablePropertyError(STIXError, ValueError):
    """Attempted to modify an unmodifiable property of object when creating a new version"""

    def __init__(self, unchangable_properties):
        super(UnmodifiablePropertyError, self).__init__()
        self.unchangable_properties = unchangable_properties

    def __str__(self):
        msg = "These properties cannot be changed when making a new version: {0}."
        return msg.format(", ".join(self.unchangable_properties))


class RevokeError(STIXError, ValueError):
    """Attempted to an operation on a revoked object"""

    def __init__(self, called_by):
        super(RevokeError, self).__init__()
        self.called_by = called_by

    def __str__(self):
        if self.called_by == "revoke":
            return "Cannot revoke an already revoked object."
        else:
            return "Cannot create a new version of a revoked object."
