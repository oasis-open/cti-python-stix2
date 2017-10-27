"""
Python STIX 2.0 FileSystem Source/Sink

TODO:
    Test everything
"""

import json
import os

from stix2.base import _STIXBase
from stix2.core import Bundle, parse
from stix2.sources import DataSink, DataSource, DataStore
from stix2.sources.filters import Filter, apply_common_filters
from stix2.utils import deduplicate


class FileSystemStore(DataStore):
    """FileSystemStore

    Provides an interface to an file directory of STIX objects.
    FileSystemStore is a wrapper around a paired FileSystemSink
    and FileSystemSource.

    Args:
        stix_dir (str): path to directory of STIX objects

    Attributes:
        source (FileSystemSource): FuleSystemSource

        sink (FileSystemSink): FileSystemSink

    """
    def __init__(self, stix_dir):
        super(FileSystemStore, self).__init__()
        self.source = FileSystemSource(stix_dir=stix_dir)
        self.sink = FileSystemSink(stix_dir=stix_dir)


class FileSystemSink(DataSink):
    """FileSystemSink

    Provides an interface for adding/pushing STIX objects
    to file directory of STIX objects.

    Can be paired with a FileSystemSource, together as the two
    components of a FileSystemStore.

    Args:
        stix_dir (str): path to directory of STIX objects

    """
    def __init__(self, stix_dir):
        super(FileSystemSink, self).__init__()
        self._stix_dir = os.path.abspath(stix_dir)

        if not os.path.exists(self._stix_dir):
            raise ValueError("directory path for STIX data does not exist")

    @property
    def stix_dir(self):
        return self._stix_dir

    def add(self, stix_data=None, allow_custom=False, version=None):
        """add STIX objects to file directory

        Args:
            stix_data (STIX object OR dict OR str OR list): valid STIX 2.0 content
                in a STIX object(or list of), dict (or list of), or a STIX 2.0
                json encoded string
            allow_custom (bool): Whether to allow custom properties or not.
                Default: False.
            version (str): Which STIX2 version to use. (e.g. "2.0", "2.1"). If
                None, use latest version.

        TODO: Bundlify STIX content or no? When dumping to disk.
        """
        def _check_path_and_write(stix_dir, stix_obj):
            path = os.path.join(stix_dir, stix_obj["type"], stix_obj["id"] + ".json")

            if not os.path.exists(os.path.dirname(path)):
                os.makedirs(os.path.dirname(path))

            with open(path, "w") as f:
                # Bundle() can take dict or STIX obj as argument
                f.write(str(Bundle(stix_obj)))

        if isinstance(stix_data, _STIXBase):
            # adding python STIX object
            _check_path_and_write(self._stix_dir, stix_data)

        elif isinstance(stix_data, dict):
            if stix_data["type"] == "bundle":
                # adding json-formatted Bundle - extracting STIX objects
                for stix_obj in stix_data["objects"]:
                    self.add(stix_obj)
            else:
                # adding json-formatted STIX
                _check_path_and_write(self._stix_dir, stix_data)

        elif isinstance(stix_data, str):
            # adding json encoded string of STIX content
            stix_data = parse(stix_data, allow_custom, version)
            if stix_data["type"] == "bundle":
                for stix_obj in stix_data["objects"]:
                    self.add(stix_obj)
            else:
                self.add(stix_data)

        elif isinstance(stix_data, list):
            # if list, recurse call on individual STIX objects
            for stix_obj in stix_data:
                self.add(stix_obj)

        else:
            raise ValueError("stix_data must be a STIX object(or list of), json formatted STIX(or list of) or a json formatted STIX bundle")


class FileSystemSource(DataSource):
    """FileSystemSource

    Provides an interface for searching/retrieving
    STIX objects from a STIX object file directory.

    Can be paired with a FileSystemSink, together as the two
    components of a FileSystemStore.

    Args:
        stix_dir (str): path to directory of STIX objects

    """
    def __init__(self, stix_dir):
        super(FileSystemSource, self).__init__()
        self._stix_dir = os.path.abspath(stix_dir)

        if not os.path.exists(self._stix_dir):
            raise ValueError("directory path for STIX data does not exist: %s" % self._stix_dir)

    @property
    def stix_dir(self):
        return self._stix_dir

    def get(self, stix_id, _composite_filters=None, allow_custom=False, version=None):
        """retrieve STIX object from file directory via STIX ID

        Args:
            stix_id (str): The STIX ID of the STIX object to be retrieved.

            _composite_filters (set): set of filters passed from the parent
                CompositeDataSource, not user supplied.
            allow_custom (bool): Whether to allow custom properties or not.
                Default: False.
            version (str): Which STIX2 version to use. (e.g. "2.0", "2.1"). If
                None, use latest version.

        Returns:
            (STIX object): STIX object that has the supplied STIX ID.
                The STIX object is loaded from its json file, parsed into
                a python STIX object and then returned

        """
        query = [Filter("id", "=", stix_id)]

        all_data = self.query(query=query, _composite_filters=_composite_filters)

        if all_data:
            stix_obj = sorted(all_data, key=lambda k: k['modified'])[0]
            stix_obj = parse(stix_obj, allow_custom, version)
        else:
            stix_obj = None

        return stix_obj

    def all_versions(self, stix_id, _composite_filters=None):
        """retrieve STIX object from file directory via STIX ID, all versions

        Note: Since FileSystem sources/sinks don't handle multiple versions
        of a STIX object, this operation is unnecessary. Pass call to get().

        Args:
            stix_id (str): The STIX ID of the STIX objects to be retrieved.

            composite_filters (set): set of filters passed from the parent
                CompositeDataSource, not user supplied

        Returns:
            (list): of STIX objects that has the supplied STIX ID.
                The STIX objects are loaded from their json files, parsed into
                a python STIX objects and then returned
        """
        return [self.get(stix_id=stix_id, _composite_filters=_composite_filters)]

    def query(self, query=None, _composite_filters=None, allow_custom=False, version=None):
        """search and retrieve STIX objects based on the complete query

        A "complete query" includes the filters from the query, the filters
        attached to MemorySource, and any filters passed from a
        CompositeDataSource (i.e. _composite_filters)

        Args:
            query (list): list of filters to search on.
            _composite_filters (set): set of filters passed from the
                CompositeDataSource, not user supplied.
            allow_custom (bool): Whether to allow custom properties or not.
                Default: False.
            version (str): Which STIX2 version to use. (e.g. "2.0", "2.1"). If
                None, use latest version.

        Returns:
            (list): list of STIX objects that matches the supplied
                query. The STIX objects are loaded from their json files,
                parsed into a python STIX objects and then returned.

        """
        all_data = []

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
                        include_paths.append(os.path.join(self._stix_dir, filter.value))
                    elif filter.op == "!=":
                        declude_paths.append(os.path.join(self._stix_dir, filter.value))
        else:
            # have to walk entire STIX directory
            include_paths.append(self._stix_dir)

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
            for dir in os.listdir(self._stix_dir):
                if os.path.abspath(dir) not in declude_paths:
                    include_paths.append(os.path.abspath(dir))

        # grab stix object ID as well - if present in filters, as
        # may forgo the loading of STIX content into memory
        if "id" in [filter.field for filter in file_filters]:
            for filter in file_filters:
                if filter.field == "id" and filter.op == "=":
                    id_ = filter.value
                    break
            else:
                id_ = None
        else:
            id_ = None

        # now iterate through all STIX objs
        for path in include_paths:
            for root, dirs, files in os.walk(path):
                for file_ in files:
                    if id_:
                        if id_ == file_.split(".")[0]:
                            # since ID is specified in one of filters, can evaluate against filename first without loading
                            stix_obj = json.load(open(os.path.join(root, file_)))["objects"][0]
                            # check against other filters, add if match
                            all_data.extend(apply_common_filters([stix_obj], query))
                    else:
                        # have to load into memory regardless to evaluate other filters
                        stix_obj = json.load(open(os.path.join(root, file_)))["objects"][0]
                        all_data.extend(apply_common_filters([stix_obj], query))

        all_data = deduplicate(all_data)

        # parse python STIX objects from the STIX object dicts
        stix_objs = [parse(stix_obj_dict, allow_custom, version) for stix_obj_dict in all_data]

        return stix_objs

    def _parse_file_filters(self, query):
        """utility method to extract STIX common filters
        that can used to possibly speed up querying STIX objects
        from the file system

        Extracts filters that are for the "id" and "type" field of
        a STIX object. As the file directory is organized by STIX
        object type with filenames that are equivalent to the STIX
        object ID, these filters can be used first to reduce the
        search space of a FileSystemStore(or FileSystemSink)
        """
        file_filters = set()
        for filter_ in query:
            if filter_.field == "id" or filter_.field == "type":
                file_filters.add(filter_)
        return file_filters
