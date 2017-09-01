"""
Python STIX 2.0 Memory Source/Sink

Classes:
    MemoryStore
    MemorySink
    MemorySource

TODO: Test everything.

TODO: Use deduplicate() calls only when memory corpus is dirty (been added to)
      can save a lot of time for successive queries

Notes:
    Not worrying about STIX versioning. The in memory STIX data at anytime
    will only hold one version of a STIX object. As such, when save() is called,
    the single versions of all the STIX objects are what is written to file.

"""

import collections
import json
import os

from stix2validator import validate_instance

from stix2 import Bundle
from stix2.sources import DataSink, DataSource, DataStore
from stix2.sources.filters import Filter


def _add(store, stix_data):
    """Adds stix objects to MemoryStore/Source/Sink."""
    if isinstance(stix_data, collections.Mapping):
        # stix objects are in a bundle
        # verify STIX json data
        r = validate_instance(stix_data)
        # make dictionary of the objects for easy lookup
        if r.is_valid:
            for stix_obj in stix_data["objects"]:
                store.data[stix_obj["id"]] = stix_obj
        else:
            raise ValueError("Error: data passed was found to not be valid by the STIX 2 Validator: \n%s", r.as_dict())
    elif isinstance(stix_data, list):
        # stix objects are in a list
        for stix_obj in stix_data:
            r = validate_instance(stix_obj)
            if r.is_valid:
                store.data[stix_obj["id"]] = stix_obj
            else:
                raise ValueError("Error: STIX object %s is not valid under STIX 2 validator.\n%s", stix_obj["id"], r)
    else:
        raise ValueError("stix_data must be in bundle format or raw list")


class MemoryStore(DataStore):
    """
    """
    def __init__(self, stix_data):
        """
        Notes:
            It doesn't make sense to create a MemoryStore by passing
            in existing MemorySource and MemorySink because there could
            be data concurrency issues. Just as easy to create new MemoryStore.

        """
        super(MemoryStore, self).__init__()
        self.data = {}

        if stix_data:
            _add(self, stix_data)

        self.source = MemorySource(stix_data=self.data, _store=True)
        self.sink = MemorySink(stix_data=self.data, _store=True)

    def save_to_file(self, file_path):
        return self.sink.save_to_file(file_path=file_path)

    def load_from_file(self, file_path):
        return self.source.load_from_file(file_path=file_path)


class MemorySink(DataSink):
    """
    """
    def __init__(self, stix_data, _store=False):
        """
        Args:
            stix_data (dictionary OR list): valid STIX 2.0 content in
                bundle or a list.
            _store (bool): if the MemorySink is a part of a DataStore,
                in which case "stix_data" is a direct reference to
                shared memory with DataSource.

        """
        super(MemorySink, self).__init__()
        self.data = {}

        if _store:
            self.data = stix_data
        elif stix_data:
            self.add(stix_data)

    def add(self, stix_data):
        """
        """
        _add(self, stix_data)

    def save_to_file(self, file_path):
        """
        """
        json.dump(Bundle(self.data.values()), file_path, indent=4)


class MemorySource(DataSource):

    def __init__(self, stix_data, _store=False):
        """
        Args:
            stix_data (dictionary OR list): valid STIX 2.0 content in
                bundle or list.
            _store (bool): if the MemorySource is a part of a DataStore,
                in which case "stix_data" is a direct reference to shared
                memory with DataSink.

        """
        super(MemorySource, self).__init__()
        self.data = {}

        if _store:
            self.data = stix_data
        elif stix_data:
            _add(self, stix_data)

    def get(self, stix_id, _composite_filters=None):
        """
        """
        if _composite_filters is None:
            # if get call is only based on 'id', no need to search, just retrieve from dict
            try:
                stix_obj = self.data[stix_id]
            except KeyError:
                stix_obj = None
            return stix_obj

        # if there are filters from the composite level, process full query
        query = [Filter("id", "=", stix_id)]

        all_data = self.query(query=query, _composite_filters=_composite_filters)

        # reduce to most recent version
        stix_obj = sorted(all_data, key=lambda k: k['modified'])[0]

        return stix_obj

    def all_versions(self, stix_id, _composite_filters=None):
        """
        Notes:
            Since Memory sources/sinks don't handle multiple versions of a
            STIX object, this operation is unnecessary. Translate call to get().

        Args:
            stix_id (str): The id of the STIX 2.0 object to retrieve. Should
                return a list of objects, all the versions of the object
                specified by the "id".

        Returns:
            (list): STIX object that matched ``stix_id``.

        """
        return [self.get(stix_id=stix_id, _composite_filters=_composite_filters)]

    def query(self, query=None, _composite_filters=None):
        """
        """
        if query is None:
            query = []

        # combine all query filters
        if self.filters:
            query.extend(list(self.filters))
        if _composite_filters:
            query.extend(_composite_filters)

        # Apply STIX common property filters.
        all_data = self.apply_common_filters(self.data.values(), query)

        return all_data

    def load_from_file(self, file_path):
        """
        """
        file_path = os.path.abspath(file_path)
        stix_data = json.load(open(file_path, "r"))

        r = validate_instance(stix_data)

        if r.is_valid:
            for stix_obj in stix_data["objects"]:
                    self.data[stix_obj["id"]] = stix_obj

        raise ValueError("Error: STIX data loaded from file (%s) was found to not be validated by STIX 2 Validator.\n%s", file_path, r)
