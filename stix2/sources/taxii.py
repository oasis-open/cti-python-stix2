"""
Python STIX 2.0 TAXII Source/Sink

TODO:
    Test everything

"""

from stix2.base import _STIXBase
from stix2.core import Bundle, parse
from stix2.sources import DataSink, DataSource, DataStore
from stix2.sources.filters import Filter, apply_common_filters
from stix2.utils import deduplicate

TAXII_FILTERS = ['added_after', 'id', 'type', 'version']


class TAXIICollectionStore(DataStore):
    """Provides an interface to a local/remote TAXII Collection
    of STIX data. TAXIICollectionStore is a wrapper
    around a paired TAXIICollectionSink and TAXIICollectionSource.

    Args:
            collection (taxii2.Collection): TAXII Collection instance
    """
    def __init__(self, collection):
        super(TAXIICollectionStore, self).__init__()
        self.source = TAXIICollectionSource(collection)
        self.sink = TAXIICollectionSink(collection)


class TAXIICollectionSink(DataSink):
    """Provides an interface for pushing STIX objects to a local/remote
    TAXII Collection endpoint.

    Args:
        collection (taxii2.Collection): TAXII2 Collection instance

    """
    def __init__(self, collection):
        super(TAXIICollectionSink, self).__init__()
        self.collection = collection

    def add(self, stix_data):
        """add/push STIX content to TAXII Collection endpoint

        Args:
            stix_data (STIX object OR dict OR str OR list): valid STIX 2.0 content
                in a STIX object (or Bundle), STIX onject dict (or Bundle dict), or a STIX 2.0
                json encoded string, or list of any of the following

        """

        if isinstance(stix_data, _STIXBase):
            # adding python STIX object
            bundle = dict(Bundle(stix_data))

        elif isinstance(stix_data, dict):
            # adding python dict (of either Bundle or STIX obj)
            if stix_data["type"] == "bundle":
                bundle = stix_data
            else:
                bundle = dict(Bundle(stix_data))

        elif isinstance(stix_data, list):
            # adding list of something - recurse on each
            for obj in stix_data:
                self.add(obj)

        elif isinstance(stix_data, str):
            # adding json encoded string of STIX content
            stix_data = parse(stix_data)
            if stix_data["type"] == "bundle":
                bundle = dict(stix_data)
            else:
                bundle = dict(Bundle(stix_data))

        else:
            raise TypeError("stix_data must be as STIX object(or list of),json formatted STIX (or list of), or a json formatted STIX bundle")

        self.collection.add_objects(bundle)


class TAXIICollectionSource(DataSource):
    """Provides an interface for searching/retrieving STIX objects
    from a local/remote TAXII Collection endpoint.

    Args:
        collection (taxii2.Collection): TAXII Collection instance

    """
    def __init__(self, collection):
        super(TAXIICollectionSource, self).__init__()
        self.collection = collection

    def get(self, stix_id, _composite_filters=None):
        """retrieve STIX object from local/remote STIX Collection
        endpoint.

        Args:
            stix_id (str): The STIX ID of the STIX object to be retrieved.

            composite_filters (set): set of filters passed from the parent
                CompositeDataSource, not user supplied

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
        stix_objs = self.collection.get_object(stix_id)["objects"]

        stix_obj = list(apply_common_filters(stix_objs, query))

        if len(stix_obj):
            stix_obj = stix_obj[0]
            stix_obj = parse(stix_obj)
        else:
            stix_obj = None

        return stix_obj

    def all_versions(self, stix_id, _composite_filters=None):
        """retrieve STIX object from local/remote TAXII Collection
        endpoint, all versions of it

        Args:
            stix_id (str): The STIX ID of the STIX objects to be retrieved.

            composite_filters (set): set of filters passed from the parent
                CompositeDataSource, not user supplied

        Returns:
            (see query() as all_versions() is just a wrapper)

        """
        # make query in TAXII query format since 'id' is TAXII field
        query = [
            Filter("match[id]", "=", stix_id),
            Filter("match[version]", "=", "all")
        ]

        all_data = self.query(query=query, _composite_filters=_composite_filters)

        return all_data

    def query(self, query=None, _composite_filters=None):
        """search and retreive STIX objects based on the complete query

        A "complete query" includes the filters from the query, the filters
        attached to MemorySource, and any filters passed from a
        CompositeDataSource (i.e. _composite_filters)

        Args:
            query (list): list of filters to search on

            composite_filters (set): set of filters passed from the
                CompositeDataSource, not user supplied

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
                query = list(query)
            query = set(query)

        # combine all query filters
        if self.filters:
            query.update(self.filters)
        if _composite_filters:
            query.update(_composite_filters)

        # separate taxii query terms (can be done remotely)
        taxii_filters = self._parse_taxii_filters(query)

        # query TAXII collection
        all_data = self.collection.get_objects(filters=taxii_filters)["objects"]

        # deduplicate data (before filtering as reduces wasted filtering)
        all_data = deduplicate(all_data)

        # apply local (CompositeDataSource, TAXIICollectionSource and query filters)
        all_data = list(apply_common_filters(all_data, query))

        # parse python STIX objects from the STIX object dicts
        stix_objs = [parse(stix_obj_dict) for stix_obj_dict in all_data]

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
            if filter_.field in TAXII_FILTERS:
                if filter_.field == "added_after":
                    params[filter_.field] = filter_.value
                else:
                    taxii_field = "match[%s]" % filter_.field
                    params[taxii_field] = filter_.value
        return params
