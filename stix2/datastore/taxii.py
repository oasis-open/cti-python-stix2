"""
Python STIX 2.x TAXIICollectionStore
"""
from requests.exceptions import HTTPError

from stix2.base import _STIXBase
from stix2.core import Bundle, parse
from stix2.datastore import DataSink, DataSource, DataStoreMixin
from stix2.datastore.filters import Filter, apply_common_filters
from stix2.utils import deduplicate

TAXII_FILTERS = ['added_after', 'id', 'type', 'version']


class TAXIICollectionStore(DataStoreMixin):
    """Provides an interface to a local/remote TAXII Collection
    of STIX data. TAXIICollectionStore is a wrapper
    around a paired TAXIICollectionSink and TAXIICollectionSource.

    Args:
        collection (taxii2.Collection): TAXII Collection instance
        allow_custom (bool): whether to allow custom STIX content to be
            pushed/retrieved. Defaults to True for TAXIICollectionSource
            side(retrieving data) and False for TAXIICollectionSink
            side(pushing data). However, when parameter is supplied, it will
            be applied to both TAXIICollectionSource/Sink.

    """
    def __init__(self, collection, allow_custom=None):
        if allow_custom is None:
            allow_custom_source = True
            allow_custom_sink = False
        else:
            allow_custom_sink = allow_custom_source = allow_custom

        super(TAXIICollectionStore, self).__init__(
            source=TAXIICollectionSource(collection, allow_custom=allow_custom_source),
            sink=TAXIICollectionSink(collection, allow_custom=allow_custom_sink)
        )


class TAXIICollectionSink(DataSink):
    """Provides an interface for pushing STIX objects to a local/remote
    TAXII Collection endpoint.

    Args:
        collection (taxii2.Collection): TAXII2 Collection instance
        allow_custom (bool): Whether to allow custom STIX content to be
            added to the TAXIICollectionSink. Default: False

    """
    def __init__(self, collection, allow_custom=False):
        super(TAXIICollectionSink, self).__init__()
        self.collection = collection
        self.allow_custom = allow_custom

    def add(self, stix_data, version=None):
        """Add/push STIX content to TAXII Collection endpoint

        Args:
            stix_data (STIX object OR dict OR str OR list): valid STIX 2.0 content
                in a STIX object (or Bundle), STIX onject dict (or Bundle dict), or a STIX 2.0
                json encoded string, or list of any of the following
            version (str): Which STIX2 version to use. (e.g. "2.0", "2.1"). If
                None, use latest version.

        """
        if isinstance(stix_data, _STIXBase):
            # adding python STIX object
            bundle = dict(Bundle(stix_data, allow_custom=self.allow_custom))

        elif isinstance(stix_data, dict):
            # adding python dict (of either Bundle or STIX obj)
            if stix_data["type"] == "bundle":
                bundle = stix_data
            else:
                bundle = dict(Bundle(stix_data, allow_custom=self.allow_custom))

        elif isinstance(stix_data, list):
            # adding list of something - recurse on each
            for obj in stix_data:
                self.add(obj, version=version)

        elif isinstance(stix_data, str):
            # adding json encoded string of STIX content
            stix_data = parse(stix_data, allow_custom=self.allow_custom, version=version)
            if stix_data["type"] == "bundle":
                bundle = dict(stix_data)
            else:
                bundle = dict(Bundle(stix_data, allow_custom=self.allow_custom))

        else:
            raise TypeError("stix_data must be as STIX object(or list of),json formatted STIX (or list of), or a json formatted STIX bundle")

        self.collection.add_objects(bundle)


class TAXIICollectionSource(DataSource):
    """Provides an interface for searching/retrieving STIX objects
    from a local/remote TAXII Collection endpoint.

    Args:
        collection (taxii2.Collection): TAXII Collection instance
        allow_custom (bool): Whether to allow custom STIX content to be
            added to the FileSystemSink. Default: True

    """
    def __init__(self, collection, allow_custom=True):
        super(TAXIICollectionSource, self).__init__()
        self.collection = collection
        self.allow_custom = allow_custom

    def get(self, stix_id, version=None, _composite_filters=None):
        """Retrieve STIX object from local/remote STIX Collection
        endpoint.

        Args:
            stix_id (str): The STIX ID of the STIX object to be retrieved.
            _composite_filters (set): set of filters passed from the parent
                CompositeDataSource, not user supplied
            version (str): Which STIX2 version to use. (e.g. "2.0", "2.1"). If
                None, use latest version.

        Returns:
            (STIX object): STIX object that has the supplied STIX ID.
                The STIX object is received from TAXII has dict, parsed into
                a python STIX object and then returned

        """
        # combine all query filters
        query = set()
        if self.filters:
            query.update(self.filters)
        if _composite_filters:
            query.update(_composite_filters)

        # dont extract TAXII filters from query (to send to TAXII endpoint)
        # as directly retrieveing a STIX object by ID
        try:
            stix_objs = self.collection.get_object(stix_id)["objects"]
            stix_obj = list(apply_common_filters(stix_objs, query))

        except HTTPError:
            # if resource not found or access is denied from TAXII server, return None
            stix_obj = []

        if len(stix_obj):
            stix_obj = parse(stix_obj[0], allow_custom=self.allow_custom, version=version)
            if stix_obj.id != stix_id:
                # check - was added to handle erroneous TAXII servers
                stix_obj = None
        else:
            stix_obj = None

        return stix_obj

    def all_versions(self, stix_id, version=None, _composite_filters=None):
        """Retrieve STIX object from local/remote TAXII Collection
        endpoint, all versions of it

        Args:
            stix_id (str): The STIX ID of the STIX objects to be retrieved.
            _composite_filters (set): set of filters passed from the parent
                CompositeDataSource, not user supplied
            version (str): Which STIX2 version to use. (e.g. "2.0", "2.1"). If
                None, use latest version.

        Returns:
            (see query() as all_versions() is just a wrapper)

        """
        # make query in TAXII query format since 'id' is TAXII field
        query = [
            Filter("match[id]", "=", stix_id),
            Filter("match[version]", "=", "all")
        ]

        all_data = self.query(query=query, _composite_filters=_composite_filters)

        # parse STIX objects from TAXII returned json
        all_data = [parse(stix_obj, allow_custom=self.allow_custom, version=version) for stix_obj in all_data]

        # check - was added to handle erroneous TAXII servers
        all_data_clean = [stix_obj for stix_obj in all_data if stix_obj.id == stix_id]

        return all_data_clean

    def query(self, query=None, version=None, _composite_filters=None):
        """Search and retreive STIX objects based on the complete query

        A "complete query" includes the filters from the query, the filters
        attached to MemorySource, and any filters passed from a
        CompositeDataSource (i.e. _composite_filters)

        Args:
            query (list): list of filters to search on
            _composite_filters (set): set of filters passed from the
                CompositeDataSource, not user supplied
            version (str): Which STIX2 version to use. (e.g. "2.0", "2.1"). If
                None, use latest version.

        Returns:
            (list): list of STIX objects that matches the supplied
                query. The STIX objects are received from TAXII as dicts,
                parsed into python STIX objects and then returned.

        """
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

        # separate taxii query terms (can be done remotely)
        taxii_filters = self._parse_taxii_filters(query)

        # query TAXII collection
        try:
            all_data = self.collection.get_objects(filters=taxii_filters)["objects"]

            # deduplicate data (before filtering as reduces wasted filtering)
            all_data = deduplicate(all_data)

            # apply local (CompositeDataSource, TAXIICollectionSource and query filters)
            all_data = list(apply_common_filters(all_data, query))

        except HTTPError:
            # if resources not found or access is denied from TAXII server, return empty list
            all_data = []

        # parse python STIX objects from the STIX object dicts
        stix_objs = [parse(stix_obj_dict, allow_custom=self.allow_custom, version=version) for stix_obj_dict in all_data]

        return stix_objs

    def _parse_taxii_filters(self, query):
        """Parse out TAXII filters that the TAXII server can filter on.

        Note:
            For instance - "?match[type]=indicator,sighting" should be in a
            query dict as follows:

            Filter("type", "=", "indicator,sighting")

        Args:
            query (list): list of filters to extract which ones are TAXII
                specific.

        Returns:
            params (dict): dict of the TAXII filters but in format required
                for 'requests.get()'.

        """
        params = {}

        for filter_ in query:
            if filter_.property in TAXII_FILTERS:
                if filter_.property == "added_after":
                    params[filter_.property] = filter_.value
                else:
                    taxii_field = "match[%s]" % filter_.property
                    params[taxii_field] = filter_.value
        return params
