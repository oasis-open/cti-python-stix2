"""
Python STIX 2.0 Memory Source/Sink

Classes:
    MemoryStore
    MemorySink
    MemorySource

TODO: Test everything.

TODO: Use deduplicate() calls only when memory corpus is dirty (been added to)
      can save a lot of time for successive queries

NOTE: Not worrying about STIX versioning. The in memory STIX data at anytime
      will only hold one version of a STIX object. As such, when save() is called,
      the single versions of all the STIX objects are what is written to file.

"""

import json
import os

from stix2 import Bundle
from stix2.sources import DataSink, DataSource, DataStore, make_id
from stix2validator import validate_string


class MemoryStore(DataStore):
    """
    """
    def __init__(self, stix_data=None, name="MemoryStore"):
        """
        Note: It doesnt make sense to create a MemoryStore by passing
         in existing MemorySource and MemorySink because there could
         be data concurrency issues. Just as easy to create new MemoryStore.
        """
        self.name = name
        self.id = make_id()
        self.data = {}

        if stix_data:
            if type(stix_data) == dict:
                # stix objects are in a bundle
                # verify STIX json data
                r = validate_string(json.dumps(stix_data))
                # make dictionary of the objects for easy lookup
                if r.is_valid:
                    for stix_obj in stix_data["objects"]:

                        self.data[stix_obj["id"]] = stix_obj
                else:
                    print("Error: json data passed to MemorySink() was found to not be validated by STIX 2 Validator")
                    print(r)
            elif type(stix_data) == list:
                # stix objects are in a list
                for stix_obj in stix_data:
                    r = validate_string(json.dumps(stix_obj))
                    if r.is_valid:
                        self.data[stix_obj["id"]] = stix_obj
                    else:
                        print("Error: STIX object %s is not valid under STIX 2 validator.") % stix_obj["id"]
                        print(r)

        self.source = MemorySource(stix_data=self.data, _store=True)
        self.sink = MemorySink(stix_data=self.data, _store=True)

    @property
    def source(self):
        return self.source

    @property
    def sink(self):
        return self.sink

    # memory sink API calls

    def add(self, stix_data):
        return self.sink.add(stix_data=stix_data)

    def save_to_file(self, file_path):
        return self.sink.save(file_path=file_path)

    # memory source API calls

    def get(self, stix_id):
        return self.source.get(stix_id=stix_id)

    def all_versions(self, stix_id):
        return self.source.all_versions(stix_id=stix_id)

    def query(self, query):
        return self.source.query(query=query)

    def load_from_file(self, file_path):
        return self.source.load_from_file(file_path=file_path)


class MemorySink(DataSink):
    """

    """
    def __init__(self, stix_data=None, name="MemorySink", _store=False):
        """
        Args:

            data (dictionary OR list): valid STIX 2.0 content in bundle or a list
            name (string): optional name tag of the data source
            _store (bool): if the MemorySink is a part of a DataStore, in which case
                           "stix_data" is a direct reference to shared memory with DataSource

        """
        super(MemorySink, self).__init__(name=name)

        if _store:
            self.data = stix_data
        else:
            self.data = {}
            if stix_data:
                if type(stix_data) == dict:
                    # stix objects are in a bundle
                    # verify STIX json data
                    r = validate_string(json.dumps(stix_data))
                    # make dictionary of the objects for easy lookup
                    if r.is_valid:
                        for stix_obj in stix_data["objects"]:

                            self.data[stix_obj["id"]] = stix_obj
                    else:
                        print("Error: json data passed to MemorySink() was found to not be validated by STIX 2 Validator")
                        print(r)
                        self.data = {}
                elif type(stix_data) == list:
                    # stix objects are in a list
                    for stix_obj in stix_data:
                        r = validate_string(json.dumps(stix_obj))
                        if r.is_valid:
                            self.data[stix_obj["id"]] = stix_obj
                        else:
                            print("Error: STIX object %s is not valid under STIX 2 validator.") % stix_obj["id"]
                            print(r)
                else:
                    raise ValueError("stix_data must be in bundle format or raw list")

    def add(self, stix_data):
        """
        """
        if type(stix_data) == dict:
            # stix data is in bundle
            r = validate_string(json.dumps(stix_data))
            if r.is_valid:
                for stix_obj in stix_data["objects"]:
                    self.data[stix_obj["id"]] = stix_obj
            else:
                print("Error: json data passed to MemorySink() was found to not be validated by STIX 2 Validator")
                print(r)
        elif type(stix_data) == list:
            # stix data is in list
            for stix_obj in stix_data:
                r = validate_string(json.dumps(stix_obj))
                if r.is_valid:
                    self.data[stix_obj["id"]] = stix_obj
                else:
                    print("Error: STIX object %s is not valid under STIX 2 validator.") % stix_obj["id"]
                    print(r)
        else:
            raise ValueError("stix_data must be in bundle format or raw list")

    def save_to_file(self, file_path):
        """
        """
        json.dump(Bundle(self.data.values()), file_path, indent=4)


class MemorySource(DataSource):

    def __init__(self, stix_data=None, name="MemorySource", _store=False):
        """
        Args:

            data (dictionary OR list): valid STIX 2.0 content in bundle or list
            name (string): optional name tag of the data source
            _store (bool): if the MemorySource is a part of a DataStore, in which case
                           "stix_data" is a direct reference to shared memory with DataSink

        """
        super(MemorySource, self).__init__(name=name)

        if _store:
            self.data = stix_data
        else:
            self.data = {}
            if stix_data:
                if type(stix_data) == dict:
                    # stix objects are in a bundle
                    # verify STIX json data
                    r = validate_string(json.dumps(stix_data))
                    # make dictionary of the objects for easy lookup
                    if r.is_valid:
                        for stix_obj in stix_data["objects"]:
                            self.data[stix_obj["id"]] = stix_obj
                    else:
                        print("Error: json data passed to MemorySink() was found to not be validated by STIX 2 Validator")
                        print(r)
                        self.data = {}
                elif type(stix_data) == list:
                    # stix objects are in a list
                    for stix_obj in stix_data:
                        r = validate_string(json.dumps(stix_obj))
                        if r.is_valid:
                            self.data[stix_obj["id"]] = stix_obj
                        else:
                            print("Error: STIX object %s is not valid under STIX 2 validator.") % stix_obj["id"]
                            print(r)
                else:
                    raise ValueError("stix_data must be in bundle format or raw list")

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
        query = [
            {
                "field": "id",
                "op": "=",
                "value": stix_id
            }
        ]

        all_data = self.query(query=query, _composite_filters=_composite_filters)

        # reduce to most recent version
        stix_obj = sorted(all_data, key=lambda k: k['modified'])[0]

        return stix_obj

    def all_versions(self, stix_id, _composite_filters=None):
        """
        NOTE: since Memory sources/sinks dont handle mutliple verions of a STIX object,
        this operation is futile. Translate call to get(). (Appoved by G.B.)
        """

        # query = [
        #     {
        #         "field": "id",
        #         "op": "=",
        #         "value": stix_id
        #     }
        # ]

        # all_data = self.query(query=query, _composite_filters=_composite_filters)

        return [self.get(stix_id=stix_id, _composite_filters=_composite_filters)]

    def query(self, query=None, _composite_filters=None):
        """

        """

        if query is None:
            query = []

        # combine all query filters
        if self.filters:
            query.extend(self.filters.values())
        if _composite_filters:
            query.extend(_composite_filters)

        # deduplicate data before filtering  -> Deduplication is not required as Memory only ever holds one version of an object
        # all_data = self.depuplicate(all_data)

        # apply STIX common property filters
        all_data = self.apply_common_filters(self.data.values(), query)

        return all_data

    def load_from_file(self, file_path):
        """
        """
        file_path = os.path.abspath(file_path)
        stix_data = json.load(open(file_path, "r"))

        r = validate_string(json.dumps(stix_data))

        if r.is_valid:
            for stix_obj in stix_data["objects"]:
                    self.data[stix_obj["id"]] = stix_obj
        else:
            print("Error: STIX data loaded from file (%s) was found to not be validated by STIX 2 Validator") % file_path
            print(r)
