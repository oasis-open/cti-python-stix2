"""
Python STIX 2.0 Data Sink (classes)


---TODO/Questions---

"""

import abc
import uuid


def make_id():
    return str(uuid.uuid4())


# STIX 2.0 fields used to denote object version
STIX_VERSION_FIELDS = ['id', 'modified']

# Currently, only STIX 2.0 common SDO fields (that are not compex objects)
# are supported for filtering on
STIX_COMMON_FIELDS = [
    'type',
    'id',
    'created_by_ref',
    'created',
    'modified',
    'revoked',
    'labels',
    # 'external_references',  # list of external references object type - not supported for filtering
    'object_references',
    'object_marking_refs',
    'granular_marking_refs',
    # 'granular_markings'  # list of granular-marking type - not supported for filtering
]


# Required fields in filter(dict)
FILTER_FIELDS = ['field', 'op', 'value']

# Supported filter operations
FILTER_OPS = ['=', '!=', 'in', '>', '<', '>=', '<=']

# Supported filter value types
FILTER_VALUE_TYPES = [bool, dict, float, int, list, str, tuple]


class DataSink(object):
    """
    Abstract Data Sink class for STIX 2.0

    An implementer will create a concrete subclass from
    this abstract class for the specific data sink.

    The purpose of the concrete subclasses is to then
    supply them to a Composite Data Source which calls
    the subclass methods when conducting STIX 2.0
    data retrievals.
    """

    __metaclass__ = abc.ABCMeta

    def __init__(self, name="DataSource"):
        self.name = name

    @abc.abstractmethod
    def save(self, object):
        """
        Fill:
            -implement the specific data source API calls, processing,
            functionality required for store data from the data sink

        Args:

            object - the object to save to the data sink

        Returns:

            success or failure as a boolean

        """
        raise NotImplementedError()

    @abc.abstractmethod
    def close(self):
        """
        Fill:
            Close, release, shutdown any objects, contexts, variables
        Args:

        Returns:
            (list): list of status/error messages
        """

        status = []

        return status
