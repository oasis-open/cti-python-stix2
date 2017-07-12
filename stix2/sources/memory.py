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
    def __init__(self, stix_data=None, source=None, sink=None, name="MemoryStore"):
        self.name = name
        self.id = make_id()

        if source:
            self.source = source
        else:
            self.source = MemorySource(stix_data=stix_data)

        if sink:
            self.sink = sink
        else:
            self.sink = MemorySink(stix_data=stix_data)

    @property
    def source(self):
        return self.source

    @source.setter
    def source(self, source):
        self.source = source

    @property
    def sink(self):
        return self.sink

    @sink.setter
    def sink(self, sink):
        self.sink = sink

    # memory sink API calls

    def add(self, stix_data):
        return self.sink.add(stix_data=stix_data)

    def remove(self, stix_ids):
        return self.sink.remove(stix_ids=stix_ids)

    def save(self):
        return self.sink.save()

    # memory source API calls

    def get(self, stix_id):
        return self.source.get(stix_id=stix_id)

    def all_versions(self, stix_id):
        return self.source.all_versions(stix_id=stix_id)

    def query(self, query):
        return self.source.query(query=query)


class MemorySink(DataSink):
    """

    """
    def __init__(self, stix_data=None, name="MemorySink"):
        """
        Args:

            data (dictionary OR list): valid STIX 2.0 content in bundle or a list
            name (string): optional name tag of the data source

        """
        super(MemorySink, self).__init__(name=name)
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

    def remove(self, stix_ids):
        """
        """
        for stix_id in stix_ids:
            try:
                del self.data[stix_id]
            except KeyError:
                pass

    def save(self, file_path=None):
        """
        """
        if not file_path:
            file_path = os.path.dirname(os.path.realpath(__file__))
        json.dump(Bundle(self.data.values()), file_path, indent=4)


class MemorySource(DataSource):

    def __init__(self, stix_data=None, name="MemorySource"):
        """
        Args:

            data (dictionary OR list): valid STIX 2.0 content in bundle or list
            name (string): optional name tag of the data source

        """
        super(MemorySource, self).__init__(name=name)
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
