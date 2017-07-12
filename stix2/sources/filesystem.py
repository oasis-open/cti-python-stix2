"""
Python STIX 2.0 FileSystem Source/Sink

Classes:
    FileSystemStore
    FileSystemSink
    FileSystemSource

TODO: Test everything
"""

import json
import os

from sources import DataSink, DataSource, DataStore, make_id
from stix2 import Bundle


class FileSystemStore(DataStore):
    """

    """
    def __init__(self, stix_dir="stix_data", name="FileSystemStore"):
        self.name = name
        self.id = make_id()
        self.source = FileSystemSource(stix_dir=stix_dir)
        self.sink = FileSystemSink(stix_dir=stix_dir)

    @property
    def source(self):
        return self.source

    @property
    def sink(self):
        return self.sink

    # file system sink API calls

    def add(self, stix_objs):
        return self.sink.add(stix_objs=stix_objs)

    # file sytem source API calls

    def get(self, stix_id):
        return self.source.get(stix_id=stix_id)

    def all_versions(self, stix_id):
        return self.source.all_versions(stix_id=stix_id)

    def query(self, query):
        return self.source.query(query=query)


class FileSystemSink(DataSink):
    """
    """
    def __init__(self, stix_dir="stix_data", name="FileSystemSink"):
        super(FileSystemSink, self).__init__(name=name)
        self.stix_dir = os.path.abspath(stix_dir)

        # check directory path exists
        if not os.path.exists(self.stix_dir):
            print("Error: directory path for STIX data does not exist")

    @property
    def stix_dir(self):
        return self.stix_dir

    @stix_dir.setter
    def stix_dir(self, dir):
        self.stix_dir = dir

    def add(self, stix_objs=None):
        """
        Q: bundlify or no?
        """
        if not stix_objs:
            stix_objs = []
        for stix_obj in stix_objs:
            path = os.path.join(self.stix_dir, stix_obj["type"], stix_obj["id"])
            json.dump(Bundle([stix_obj]), open(path, 'w+', indent=4))


class FileSystemSource(DataSource):
    """
    """
    def __init__(self, stix_dir="stix_data", name="FileSystemSource"):
        super(FileSystemSource, self).__init__(name=name)
        self.stix_dir = os.path.abspath(stix_dir)

        # check directory path exists
        if not os.path.exists(self.stix_dir):
            print("Error: directory path for STIX data does not exist")

    @property
    def stix_dir(self):
        return self.stix_dir

    @stix_dir.setter
    def stix_dir(self, dir):
        self.stix_dir = dir

    def get(self, stix_id, _composite_filters=None):
        """
        """
        query = [
            {
                "field": "id",
                "op": "=",
                "value": stix_id
            }
        ]

        all_data = self.query(query=query, _composite_filters=_composite_filters)

        stix_obj = sorted(all_data, key=lambda k: k['modified'])[0]

        return stix_obj

    def all_versions(self, stix_id, _composite_filters=None):
        """
        NOTE: since FileSystem sources/sinks dont handle mutliple verions of a STIX object,
        this operation is futile. Pass call to get(). (Appoved by G.B.)
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
        all_data = []

        if query is None:
            query = []

        # combine all query filters
        if self.filters:
            query.extend(self.filters.values())
        if _composite_filters:
            query.extend(_composite_filters)

        # extract any filters that are for "type" or "id" , as we can then do
        # filtering before reading in the STIX objects. A STIX 'type' filter
        # can reduce the query to a single sub-directory. A STIX 'id' filter
        # allows for the fast checking of the file names versus loading it.
        file_filters = self._parse_file_filters(query)

        # establish which subdirectories can be avoided in query
        # by decluding as many as possible. A filter with "type" as the field
        # means that certain STIX object types can be ruled out, and thus
        # the corresponding subdirectories as well
        include_paths = []
        declude_paths = []
        if "type" in [filter_["field"] for filter_ in file_filters]:
            for filter_ in file_filters:
                if filter_["field"] == "type":
                    if filter_["op"] == '=':
                        include_paths.append(os.path.join(self.stix_dir, filter_["value"]))
                    elif filter_["op"] == "!=":
                        declude_paths.append(os.path.join(self.stix_dir, filter_["value"]))
        else:
            # have to walk entire STIX directory
            include_paths.append(self.stix_dir)

        # if a user specifies a "type" filter like "type = <stix-object_type>",
        # the filter is reducing the search space to single stix object types
        # (and thus single directories). This makes such a filter more powerful
        # than "type != <stix-object_type>" bc the latter is substracting
        # only one type of stix object type (and thus only one directory),
        # As such the former type of filters are given preference over the latter;
        # i.e. if both exist in a query, that latter type will be ignored

        if not include_paths:
            # user has specified types that are not wanted (i.e. "!=")
            # so query will look in all STIX directories that are not
            # the specified type. Compile correct dir paths
            for dir_ in os.listdir(self.stix_dir):
                if os.path.abspath(dir_) not in declude_paths:
                    include_paths.append(os.path.abspath(dir_))

        # grab stix object ID as well - if present in filters, as
        # may forgo the loading of STIX content into memory
        if "id" in [filter_["field"] for filter_ in file_filters]:
            for filter_ in file_filters:
                if filter_["field"] == "id" and filter_["field"] == '=':
                    id_ = filter_["value"]
        else:
            id_ = None

        # now iterate through all STIX objs
        for path in include_paths:
            for root, dirs, files in os.walk(path):
                for file_ in files:
                    if id_:
                        if id_ == file_.split(".")[0]:
                            # since ID is specified in one of filters, can evaluate against filename first without loading
                            stix_obj = json.load(file_)["objects"]
                            # check against other filters, add if match
                            all_data.extend(self.apply_common_filters([stix_obj], query))
                    else:
                        # have to load into memory regardless to evaluate other filters
                        stix_obj = json.load(file_)["objects"]
                        all_data.extend(self.apply_common_filters([stix_obj], query))

        all_data = self.deduplicate(all_data)

        return all_data

    def _parse_file_filters(self, query):
        """
        """
        file_filters = []
        for filter_ in query:
            if filter_["field"] == "id" or filter_["field"] == "type":
                file_filters.append(filter_)
        return file_filters
