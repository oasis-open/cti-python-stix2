class STIXError(Exception):
    """Base class for errors generated in the stix2 library."""


class STIXValueError(STIXError, ValueError):
    """An invalid value was provided to a STIX object's __init__."""

    def __init__(self, cls, prop_name, reason):
        self.cls = cls
        self.prop_name = prop_name
        self.reason = reason

    def __str__(self):
        msg = "Invalid value for {0.cls.__name__} '{0.prop_name}': {0.reason}"
        return msg.format(self)
