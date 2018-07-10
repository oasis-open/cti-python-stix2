"""
Python STIX 2.0 Memory Source/Sink

TODO:
    Use deduplicate() calls only when memory corpus is dirty (been added to)
    can save a lot of time for successive queries

Note:
    Not worrying about STIX versioning. The in memory STIX data at anytime
    will only hold one version of a STIX object. As such, when save() is called,
    the single versions of all the STIX objects are what is written to file.

"""

import collections
import io
import json
import os

from stix2 import Bundle, v20
from stix2.core import parse
from stix2.datastore import DataSink, DataSource, DataStoreMixin
from stix2.datastore.filters import Filter, FilterSet, apply_common_filters


def _add(store, stix_data=None):
    """Add STIX objects to MemoryStore/Sink.

    Adds STIX objects to an in-memory dictionary for fast lookup.
    Recursive function, breaks down STIX Bundles and lists.

    Args:
        stix_data (list OR dict OR STIX object): STIX objects to be added

    """
    if isinstance(stix_data, collections.Mapping):
        if stix_data['type'] == 'bundle':
            # adding a json bundle - so just grab STIX objects
            for stix_obj in stix_data.get('objects', []):
                _add(store, stix_obj)
        else:
            # adding a json STIX object
            store._data[stix_data['id']] = stix_data

    elif isinstance(stix_data, list):
        # STIX objects are in a list- recurse on each object
        for stix_obj in stix_data:
            _add(store, stix_obj)

    else:
        raise TypeError("stix_data expected to be a python-stix2 object (or list of), JSON formatted STIX (or list of),"
                        " or a JSON formatted STIX bundle. stix_data was of type: " + str(type(stix_data)))


class MemoryStore(DataStoreMixin):
    """Interface to an in-memory dictionary of STIX objects.

    MemoryStore is a wrapper around a paired MemorySink and MemorySource.

    Note: It doesn't make sense to create a MemoryStore by passing
    in existing MemorySource and MemorySink because there could
    be data concurrency issues. As well, just as easy to create new MemoryStore.

    Args:
        stix_data (list OR dict OR STIX object): STIX content to be added
        allow_custom (bool): whether to allow custom STIX content.
            Only applied when export/input functions called, i.e.
            load_from_file() and save_to_file(). Defaults to True.

    Attributes:
        _data (dict): the in-memory dict that holds STIX objects
        source (MemorySource): MemorySource
        sink (MemorySink): MemorySink

    """
    def __init__(self, stix_data=None, allow_custom=True):
        self._data = {}

        if stix_data:
            _add(self, stix_data)

        super(MemoryStore, self).__init__(
            source=MemorySource(stix_data=self._data, allow_custom=allow_custom, _store=True),
            sink=MemorySink(stix_data=self._data, allow_custom=allow_custom, _store=True)
        )

    def save_to_file(self, *args, **kwargs):
        """Write SITX objects from in-memory dictionary to JSON file, as a STIX
        Bundle. If a directory is given, the Bundle 'id' will be used as
        filename. Otherwise, the provided value will be used.

        Args:
            path (str): file path to write STIX data to.
            encoding (str): The file encoding. Default utf-8.

        """
        return self.sink.save_to_file(*args, **kwargs)

    def load_from_file(self, *args, **kwargs):
        """Load STIX data from JSON file.

        File format is expected to be a single JSON STIX object or JSON STIX
        bundle.

        Args:
            path (str): file path to load STIX data from

        """
        return self.source.load_from_file(*args, **kwargs)


class MemorySink(DataSink):
    """Interface for adding/pushing STIX objects to an in-memory dictionary.

    Designed to be paired with a MemorySource, together as the two
    components of a MemoryStore.

    Args:
        stix_data (dict OR list): valid STIX 2.0 content in
            bundle or a list.
        _store (bool): whether the MemorySink is a part of a MemoryStore,
            in which case "stix_data" is a direct reference to
            shared memory with DataSource. Not user supplied
        allow_custom (bool): whether to allow custom objects/properties
            when exporting STIX content to file.
            Default: True.

    Attributes:
        _data (dict): the in-memory dict that holds STIX objects.
            If part of a MemoryStore, the dict is shared with a MemorySource

    """
    def __init__(self, stix_data=None, allow_custom=True, _store=False):
        super(MemorySink, self).__init__()
        self._data = {}
        self.allow_custom = allow_custom

        if _store:
            self._data = stix_data
        elif stix_data:
            _add(self, stix_data)

    def add(self, stix_data):
        _add(self, stix_data)
    add.__doc__ = _add.__doc__

    def save_to_file(self, path, encoding='utf-8'):
        path = os.path.abspath(path)
        all_objs = list(self._data.values())

        if any('spec_version' in x for x in all_objs):
            bundle = Bundle(all_objs, allow_custom=self.allow_custom)
        else:
            bundle = v20.Bundle(all_objs, allow_custom=self.allow_custom)

        if not os.path.exists(os.path.dirname(path)):
            os.makedirs(os.path.dirname(path))

        # if the user only provided a directory, use the bundle id for filename
        if os.path.isdir(path):
            path = os.path.join(path, bundle['id'] + '.json')

        with io.open(path, 'w', encoding=encoding) as f:
            bundle = bundle.serialize(pretty=True, encoding=encoding, ensure_ascii=False)
            f.write(bundle)
    save_to_file.__doc__ = MemoryStore.save_to_file.__doc__


class MemorySource(DataSource):
    """Interface for searching/retrieving STIX objects from an in-memory
    dictionary.

    Designed to be paired with a MemorySink, together as the two
    components of a MemoryStore.

    Args:
        stix_data (dict OR list OR STIX object): valid STIX 2.0 content in
            bundle or list.
        _store (bool): if the MemorySource is a part of a MemoryStore,
            in which case "stix_data" is a direct reference to shared
            memory with DataSink. Not user supplied
        allow_custom (bool): whether to allow custom objects/properties
            when importing STIX content from file.
            Default: True.

    Attributes:
        _data (dict): the in-memory dict that holds STIX objects.
            If part of a MemoryStore, the dict is shared with a MemorySink

    """
    def __init__(self, stix_data=None, allow_custom=True, _store=False):
        super(MemorySource, self).__init__()
        self._data = {}
        self.allow_custom = allow_custom

        if _store:
            self._data = stix_data
        elif stix_data:
            _add(self, stix_data)

    def get(self, stix_id, _composite_filters=None):
        """Retrieve STIX object from in-memory dict via STIX ID.

        Args:
            stix_id (str): The STIX ID of the STIX object to be retrieved.
            _composite_filters (FilterSet): collection of filters passed from the parent
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
        query = [Filter('id', '=', stix_id)]

        all_data = self.query(query=query, _composite_filters=_composite_filters)

        if all_data:
            # reduce to most recent version
            stix_obj = sorted(all_data, key=lambda k: k['modified'])[0]

            return stix_obj
        else:
            return None

    def all_versions(self, stix_id, _composite_filters=None):
        """Retrieve STIX objects from in-memory dict via STIX ID, all versions
        of it.

        Note: Since Memory sources/sinks don't handle multiple versions of a
        STIX object, this operation is unnecessary. Translate call to get().

        Args:
            stix_id (str): The STIX ID of the STIX 2 object to retrieve.
            _composite_filters (FilterSet): collection of filters passed from
                the parent CompositeDataSource, not user supplied

        Returns:
            (list): list of STIX objects that has the supplied ID. As the
                MemoryStore(i.e. MemorySink) adds STIX objects to memory as they
                are supplied (either as python dictionary or STIX object), it
                is returned in the same form as it as added

        """

        return [self.get(stix_id=stix_id, _composite_filters=_composite_filters)]

    def query(self, query=None, _composite_filters=None):
        """Search and retrieve STIX objects based on the complete query.

        A "complete query" includes the filters from the query, the filters
        attached to this MemorySource, and any filters passed from a
        CompositeDataSource (i.e. _composite_filters).

        Args:
            query (list): list of filters to search on
            _composite_filters (FilterSet): collection of filters passed from
                the CompositeDataSource, not user supplied

        Returns:
            (list): list of STIX objects that matches the supplied
                query. As the MemoryStore(i.e. MemorySink) adds STIX objects
                to memory as they are supplied (either as python dictionary or
                STIX object), it is returned in the same form as it as added.

        """
        query = FilterSet(query)

        # combine all query filters
        if self.filters:
            query.add(self.filters)
        if _composite_filters:
            query.add(_composite_filters)

        # Apply STIX common property filters.
        all_data = list(apply_common_filters(self._data.values(), query))

        return all_data

    def load_from_file(self, file_path):
        stix_data = json.load(open(os.path.abspath(file_path), 'r'))

        if stix_data['type'] == 'bundle':
            for stix_obj in stix_data['objects']:
                _add(self, stix_data=parse(stix_obj, allow_custom=self.allow_custom))
        else:
            _add(self, stix_data=parse(stix_data, allow_custom=self.allow_custom))
    load_from_file.__doc__ = MemoryStore.load_from_file.__doc__
