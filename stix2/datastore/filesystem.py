"""
Python STIX 2.0 FileSystem Source/Sink

"""

import json
import os

from stix2.core import Bundle, parse
from stix2.datastore import DataSink, DataSource, DataStoreMixin
from stix2.datastore.filters import Filter, apply_common_filters
from stix2.utils import deduplicate, get_class_hierarchy_names


class FileSystemStore(DataStoreMixin):
    """Interface to a file directory of STIX objects.

    FileSystemStore is a wrapper around a paired FileSystemSink
    and FileSystemSource.

    Args:
        stix_dir (str): path to directory of STIX objects
        allow_custom (bool): whether to allow custom STIX content to be
            pushed/retrieved. Defaults to True for FileSystemSource side(retrieving data)
            and False for FileSystemSink side(pushing data). However, when
            parameter is supplied, it will be applied to both FileSystemSource
            and FileSystemSink.
        bundlify (bool): whether to wrap objects in bundles when saving them.
            Default: False.

    Attributes:
        source (FileSystemSource): FileSystemSource
        sink (FileSystemSink): FileSystemSink

    """
    def __init__(self, stix_dir, allow_custom=None, bundlify=False):
        if allow_custom is None:
            allow_custom_source = True
            allow_custom_sink = False
        else:
            allow_custom_sink = allow_custom_source = allow_custom

        super(FileSystemStore, self).__init__(
            source=FileSystemSource(stix_dir=stix_dir, allow_custom=allow_custom_source),
            sink=FileSystemSink(stix_dir=stix_dir, allow_custom=allow_custom_sink, bundlify=bundlify)
        )


class FileSystemSink(DataSink):
    """Interface for adding/pushing STIX objects to file directory of STIX
    objects.

    Can be paired with a FileSystemSource, together as the two
    components of a FileSystemStore.

    Args:
        stix_dir (str): path to directory of STIX objects.
        allow_custom (bool): Whether to allow custom STIX content to be
            added to the FileSystemSource. Default: False
        bundlify (bool): Whether to wrap objects in bundles when saving them.
            Default: False.

    """
    def __init__(self, stix_dir, allow_custom=False, bundlify=False):
        super(FileSystemSink, self).__init__()
        self._stix_dir = os.path.abspath(stix_dir)
        self.allow_custom = allow_custom
        self.bundlify = bundlify

        if not os.path.exists(self._stix_dir):
            raise ValueError("directory path for STIX data does not exist")

    @property
    def stix_dir(self):
        return self._stix_dir

    def _check_path_and_write(self, stix_obj):
        """Write the given STIX object to a file in the STIX file directory.
        """
        path = os.path.join(self._stix_dir, stix_obj["type"], stix_obj["id"] + ".json")

        if not os.path.exists(os.path.dirname(path)):
            os.makedirs(os.path.dirname(path))

        if self.bundlify:
            stix_obj = Bundle(stix_obj, allow_custom=self.allow_custom)

        with open(path, "w") as f:
            f.write(str(stix_obj))

    def add(self, stix_data=None, version=None):
        """Add STIX objects to file directory.

        Args:
            stix_data (STIX object OR dict OR str OR list): valid STIX 2.0 content
                in a STIX object (or list of), dict (or list of), or a STIX 2.0
                json encoded string.
            version (str): Which STIX2 version to use. (e.g. "2.0", "2.1"). If
                None, use latest version.

        Note:
            ``stix_data`` can be a Bundle object, but each object in it will be
            saved separately; you will be able to retrieve any of the objects
            the Bundle contained, but not the Bundle itself.

        """
        if any(x in ('STIXDomainObject', 'STIXRelationshipObject', 'MarkingDefinition')
               for x in get_class_hierarchy_names(stix_data)):
            # adding python STIX object
            self._check_path_and_write(stix_data)

        elif isinstance(stix_data, (str, dict)):
            stix_data = parse(stix_data, allow_custom=self.allow_custom, version=version)
            if stix_data["type"] == "bundle":
                # extract STIX objects
                for stix_obj in stix_data.get("objects", []):
                    self.add(stix_obj, version=version)
            else:
                # adding json-formatted STIX
                self._check_path_and_write(stix_data,)

        elif isinstance(stix_data, Bundle):
            # recursively add individual STIX objects
            for stix_obj in stix_data.get("objects", []):
                self.add(stix_obj, version=version)

        elif isinstance(stix_data, list):
            # recursively add individual STIX objects
            for stix_obj in stix_data:
                self.add(stix_obj, version=version)

        else:
            raise TypeError("stix_data must be a STIX object (or list of), "
                            "JSON formatted STIX (or list of), "
                            "or a JSON formatted STIX bundle")


class FileSystemSource(DataSource):
    """Interface for searching/retrieving STIX objects from a STIX object file
    directory.

    Can be paired with a FileSystemSink, together as the two
    components of a FileSystemStore.

    Args:
        stix_dir (str): path to directory of STIX objects
        allow_custom (bool): Whether to allow custom STIX content to be
            added to the FileSystemSink. Default: True

    """
    def __init__(self, stix_dir, allow_custom=True):
        super(FileSystemSource, self).__init__()
        self._stix_dir = os.path.abspath(stix_dir)
        self.allow_custom = allow_custom

        if not os.path.exists(self._stix_dir):
            raise ValueError("directory path for STIX data does not exist: %s" % self._stix_dir)

    @property
    def stix_dir(self):
        return self._stix_dir

    def get(self, stix_id, version=None, _composite_filters=None):
        """Retrieve STIX object from file directory via STIX ID.

        Args:
            stix_id (str): The STIX ID of the STIX object to be retrieved.
            _composite_filters (set): set of filters passed from the parent
                CompositeDataSource, not user supplied
            version (str): Which STIX2 version to use. (e.g. "2.0", "2.1"). If
                None, use latest version.

        Returns:
            (STIX object): STIX object that has the supplied STIX ID.
                The STIX object is loaded from its json file, parsed into
                a python STIX object and then returned

        """
        query = [Filter("id", "=", stix_id)]

        all_data = self.query(query=query, version=version, _composite_filters=_composite_filters)

        if all_data:
            stix_obj = sorted(all_data, key=lambda k: k['modified'])[0]
        else:
            stix_obj = None

        return stix_obj

    def all_versions(self, stix_id, version=None, _composite_filters=None):
        """Retrieve STIX object from file directory via STIX ID, all versions.

        Note: Since FileSystem sources/sinks don't handle multiple versions
        of a STIX object, this operation is unnecessary. Pass call to get().

        Args:
            stix_id (str): The STIX ID of the STIX objects to be retrieved.
            _composite_filters (set): set of filters passed from the parent
                CompositeDataSource, not user supplied
            version (str): Which STIX2 version to use. (e.g. "2.0", "2.1"). If
                None, use latest version.

        Returns:
            (list): of STIX objects that has the supplied STIX ID.
                The STIX objects are loaded from their json files, parsed into
                a python STIX objects and then returned

        """
        return [self.get(stix_id=stix_id, version=version, _composite_filters=_composite_filters)]

    def query(self, query=None, version=None, _composite_filters=None):
        """Search and retrieve STIX objects based on the complete query.

        A "complete query" includes the filters from the query, the filters
        attached to this FileSystemSource, and any filters passed from a
        CompositeDataSource (i.e. _composite_filters).

        Args:
            query (list): list of filters to search on
            _composite_filters (set): set of filters passed from the
                CompositeDataSource, not user supplied
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
                query = [query]
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
        # by decluding as many as possible. A filter with "type" as the property
        # means that certain STIX object types can be ruled out, and thus
        # the corresponding subdirectories as well
        include_paths = []
        declude_paths = []
        if "type" in [filter.property for filter in file_filters]:
            for filter in file_filters:
                if filter.property == "type":
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
                if os.path.abspath(os.path.join(self._stix_dir, dir)) not in declude_paths:
                    include_paths.append(os.path.abspath(os.path.join(self._stix_dir, dir)))

        # grab stix object ID as well - if present in filters, as
        # may forgo the loading of STIX content into memory
        if "id" in [filter.property for filter in file_filters]:
            for filter in file_filters:
                if filter.property == "id" and filter.op == "=":
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
                    if not id_ or id_ == file_.split(".")[0]:
                        # have to load into memory regardless to evaluate other filters
                        stix_obj = json.load(open(os.path.join(root, file_)))
                        if stix_obj.get('type', '') == 'bundle':
                            stix_obj = stix_obj['objects'][0]
                        # check against other filters, add if match
                        all_data.extend(apply_common_filters([stix_obj], query))

        all_data = deduplicate(all_data)

        # parse python STIX objects from the STIX object dicts
        stix_objs = [parse(stix_obj_dict, allow_custom=self.allow_custom, version=version) for stix_obj_dict in all_data]

        return stix_objs

    def _parse_file_filters(self, query):
        """Extract STIX common filters.

        Possibly speeds up querying STIX objects from the file system.

        Extracts filters that are for the "id" and "type" property of
        a STIX object. As the file directory is organized by STIX
        object type with filenames that are equivalent to the STIX
        object ID, these filters can be used first to reduce the
        search space of a FileSystemStore (or FileSystemSink).

        """
        file_filters = set()
        for filter_ in query:
            if filter_.property == "id" or filter_.property == "type":
                file_filters.add(filter_)
        return file_filters
