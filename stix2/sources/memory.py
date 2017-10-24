"""
Python STIX 2.0 Memory Source/Sink

TODO:
    Run through tests again, lot of changes.

TODO:
    Use deduplicate() calls only when memory corpus is dirty (been added to)
    can save a lot of time for successive queries

Note:
    Not worrying about STIX versioning. The in memory STIX data at anytime
    will only hold one version of a STIX object. As such, when save() is called,
    the single versions of all the STIX objects are what is written to file.

"""

import json
import os

from stix2.base import _STIXBase
from stix2.core import Bundle, parse
from stix2.sources import DataSink, DataSource, DataStore
from stix2.sources.filters import Filter, apply_common_filters


def _add(store, stix_data=None):
    """Adds STIX objects to MemoryStore/Sink.

    Adds STIX objects to an in-memory dictionary for fast lookup.
    Recursive function, breaks down STIX Bundles and lists.

    Args:
        stix_data (list OR dict OR STIX object): STIX objects to be added
    """

    if isinstance(stix_data, _STIXBase):
        # adding a python STIX object
        store._data[stix_data["id"]] = stix_data

    elif isinstance(stix_data, dict):
        if stix_data["type"] == "bundle":
            # adding a json bundle - so just grab STIX objects
            for stix_obj in stix_data["objects"]:
                _add(store, stix_obj)
        else:
            # adding a json STIX object
            store._data[stix_data["id"]] = stix_data

    elif isinstance(stix_data, str):
        # adding json encoded string of STIX content
        stix_data = parse(stix_data)
        if stix_data["type"] == "bundle":
            # recurse on each STIX object in bundle
            for stix_obj in stix_data:
                _add(store, stix_obj)
        else:
            _add(store, stix_data)

    elif isinstance(stix_data, list):
        # STIX objects are in a list- recurse on each object
        for stix_obj in stix_data:
            _add(store, stix_obj)

    else:
        raise TypeError("stix_data must be as STIX object(or list of),json formatted STIX (or list of), or a json formatted STIX bundle")


class MemoryStore(DataStore):
    """Provides an interface to an in-memory dictionary
    of STIX objects. MemoryStore is a wrapper around a paired
    MemorySink and MemorySource

    Note: It doesn't make sense to create a MemoryStore by passing
    in existing MemorySource and MemorySink because there could
    be data concurrency issues. As well, just as easy to create new MemoryStore.

    Args:
        stix_data (list OR dict OR STIX object): STIX content to be added

    Attributes:
        _data (dict): the in-memory dict that holds STIX objects

        source (MemorySource): MemorySource

        sink (MemorySink): MemorySink

    """

    def __init__(self, stix_data=None):
        super(MemoryStore, self).__init__()
        self._data = {}

        if stix_data:
            _add(self, stix_data)

        self.source = MemorySource(stix_data=self._data, _store=True)
        self.sink = MemorySink(stix_data=self._data, _store=True)

    def save_to_file(self, file_path):
        return self.sink.save_to_file(file_path=file_path)

    def load_from_file(self, file_path):
        return self.source.load_from_file(file_path=file_path)


class MemorySink(DataSink):
    """Provides an interface for adding/pushing STIX objects
    to an in-memory dictionary.

    Designed to be paired with a MemorySource, together as the two
    components of a MemoryStore.

    Args:
        stix_data (dict OR list): valid STIX 2.0 content in
            bundle or a list.

        _store (bool): if the MemorySink is a part of a DataStore,
            in which case "stix_data" is a direct reference to
            shared memory with DataSource. Not user supplied

    Attributes:
        _data (dict): the in-memory dict that holds STIX objects.
            If apart of a MemoryStore, dict is shared between with
            a MemorySource
    """

    def __init__(self, stix_data=None, _store=False):
        super(MemorySink, self).__init__()
        self._data = {}

        if _store:
            self._data = stix_data
        elif stix_data:
            _add(self, stix_data)

    def add(self, stix_data):
        """add STIX objects to in-memory dictionary maintained by
        the MemorySink (MemoryStore)

        see "_add()" for args documentation
        """
        _add(self, stix_data)

    def save_to_file(self, file_path):
        """write SITX objects in in-memory dictionary to json file, as a STIX Bundle

        Args:
            file_path (str): file path to write STIX data to

        """
        file_path = os.path.abspath(file_path)
        if not os.path.exists(os.path.dirname(file_path)):
            os.makedirs(os.path.dirname(file_path))
        with open(file_path, "w") as f:
            f.write(str(Bundle(self._data.values())))


class MemorySource(DataSource):
    """Provides an interface for searching/retrieving
    STIX objects from an in-memory dictionary.

    Designed to be paired with a MemorySink, together as the two
    components of a MemoryStore.

    Args:
        stix_data (dict OR list OR STIX object): valid STIX 2.0 content in
            bundle or list.

        _store (bool): if the MemorySource is a part of a DataStore,
            in which case "stix_data" is a direct reference to shared
            memory with DataSink. Not user supplied

    Attributes:
        _data (dict): the in-memory dict that holds STIX objects.
            If apart of a MemoryStore, dict is shared between with
            a MemorySink
    """

    def __init__(self, stix_data=None, _store=False):
        super(MemorySource, self).__init__()
        self._data = {}

        if _store:
            self._data = stix_data
        elif stix_data:
            _add(self, stix_data)

    def get(self, stix_id, _composite_filters=None):
        """retrieve STIX object from in-memory dict via STIX ID

        Args:
            stix_id (str): The STIX ID of the STIX object to be retrieved.

            composite_filters (set): set of filters passed from the parent
                CompositeDataSource, not user supplied

        Returns:
            (dict OR STIX object): STIX object that has the supplied
                ID. As the MemoryStore(i.e. MemorySink) adds STIX objects to memory
                as they are supplied (either as python dictionary or STIX object), it
                is returned in the same form as it as added
        """

        if _composite_filters is None:
            # if get call is only based on 'id', no need to search, just retrieve from dict
            try:
                stix_obj = self._data[stix_id]
            except KeyError:
                stix_obj = None
            return stix_obj

        # if there are filters from the composite level, process full query
        query = [Filter("id", "=", stix_id)]

        all_data = self.query(query=query, _composite_filters=_composite_filters)

        if all_data:
            print(all_data)
            # reduce to most recent version
            stix_obj = sorted(all_data, key=lambda k: k['modified'])[0]

            return stix_obj
        else:
            return None

    def all_versions(self, stix_id, _composite_filters=None):
        """retrieve STIX objects from in-memory dict via STIX ID, all versions of it

        Note: Since Memory sources/sinks don't handle multiple versions of a
        STIX object, this operation is unnecessary. Translate call to get().

        Args:
            stix_id (str): The STIX ID of the STIX 2 object to retrieve.

            composite_filters (set): set of filters passed from the parent
                CompositeDataSource, not user supplied

        Returns:
            (list): list of STIX objects that has the supplied ID. As the
                MemoryStore(i.e. MemorySink) adds STIX objects to memory as they
                are supplied (either as python dictionary or STIX object), it
                is returned in the same form as it as added

        """
        return [self.get(stix_id=stix_id, _composite_filters=_composite_filters)]

    def query(self, query=None, _composite_filters=None):
        """search and retrieve STIX objects based on the complete query

        A "complete query" includes the filters from the query, the filters
        attached to MemorySource, and any filters passed from a
        CompositeDataSource (i.e. _composite_filters)

        Args:
            query (list): list of filters to search on

            composite_filters (set): set of filters passed from the
                CompositeDataSource, not user supplied

        Returns:
            (list): list of STIX objects that matches the supplied
                query. As the MemoryStore(i.e. MemorySink) adds STIX objects to memory
                as they are supplied (either as python dictionary or STIX object), it
                is returned in the same form as it as added

        """
        if query is None:
            query = set()
        else:
            if not isinstance(query, list):
                # make sure dont make set from a Filter object,
                # need to make a set from a list of Filter objects (even if just one Filter)
                query = list(query)
            query = set(query)

        # combine all query filters
        if self.filters:
            query.update(self.filters)
        if _composite_filters:
            query.update(_composite_filters)

        # Apply STIX common property filters.
        all_data = list(apply_common_filters(self._data.values(), query))

        return all_data

    def load_from_file(self, file_path):
        """load STIX data from json file

        File format is expected to be a single json
        STIX object or json STIX bundle

        Args:
            file_path (str): file path to load STIX data from
        """
        file_path = os.path.abspath(file_path)
        stix_data = json.load(open(file_path, "r"))
        _add(self, stix_data)
