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

from stix2 import Bundle
from stix2.sources import DataSink, DataSource, DataStore, Filter


class FileSystemStore(DataStore):
    """
    """
    def __init__(self, stix_dir="stix_data"):
        super(FileSystemStore, self).__init__()
        self.source = FileSystemSource(stix_dir=stix_dir)
        self.sink = FileSystemSink(stix_dir=stix_dir)


class FileSystemSink(DataSink):
    """
    """
    def __init__(self, stix_dir="stix_data"):
        super(FileSystemSink, self).__init__()
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
            json.dump(Bundle([stix_obj]), open(path, 'w+'), indent=4)


class FileSystemSource(DataSource):
    """
    """
    def __init__(self, stix_dir="stix_data"):
        super(FileSystemSource, self).__init__()
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
        query = [Filter("id", "=", stix_id)]

        all_data = self.query(query=query, _composite_filters=_composite_filters)

        stix_obj = sorted(all_data, key=lambda k: k['modified'])[0]

        return stix_obj

    def all_versions(self, stix_id, _composite_filters=None):
        """
        Notes:
            Since FileSystem sources/sinks don't handle multiple versions
            of a STIX object, this operation is futile. Pass call to get().
            (Approved by G.B.)

        """
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
        if "type" in [filter.field for filter in file_filters]:
            for filter in file_filters:
                if filter.field == "type":
                    if filter.op == "=":
                        include_paths.append(os.path.join(self.stix_dir, filter.value))
                    elif filter.op == "!=":
                        declude_paths.append(os.path.join(self.stix_dir, filter.value))
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
            for dir in os.listdir(self.stix_dir):
                if os.path.abspath(dir) not in declude_paths:
                    include_paths.append(os.path.abspath(dir))

        # grab stix object ID as well - if present in filters, as
        # may forgo the loading of STIX content into memory
        if "id" in [filter.field for filter in file_filters]:
            for filter in file_filters:
                if filter.field == "id" and filter.op == "=":
                    id = filter.value
                    break
            else:
                id = None
        else:
            id = None

        # now iterate through all STIX objs
        for path in include_paths:
            for root, dirs, files in os.walk(path):
                for file in files:
                    if id:
                        if id == file.split(".")[0]:
                            # since ID is specified in one of filters, can evaluate against filename first without loading
                            stix_obj = json.load(file)["objects"]
                            # check against other filters, add if match
                            all_data.extend(self.apply_common_filters([stix_obj], query))
                    else:
                        # have to load into memory regardless to evaluate other filters
                        stix_obj = json.load(file)["objects"]
                        all_data.extend(self.apply_common_filters([stix_obj], query))

        all_data = self.deduplicate(all_data)
        return all_data

    def _parse_file_filters(self, query):
        """
        """
        file_filters = []
        for filter in query:
            if filter.field == "id" or filter.field == "type":
                file_filters.append(filter)
        return file_filters
