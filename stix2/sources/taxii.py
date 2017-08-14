"""
Python STIX 2.0 TAXII Source/Sink

Classes:
    TAXIICollectionStore
    TAXIICollectionSink
    TAXIICollectionSource

TODO: Test everything

"""

import json

from stix2.sources import DataSink, DataSource, DataStore, make_id

TAXII_FILTERS = ['added_after', 'id', 'type', 'version']


class TAXIICollectionStore(DataStore):
    """
    """
    def __init__(self, collection, name="TAXIICollectionStore"):
        """
        Create a new TAXII Collection Data store

        Args:
            collection (taxii2.Collection): Collection instance

        """
        super(TAXIICollectionStore, self).__init__(name=name)
        self.source = TAXIICollectionSource(collection)
        self.sink = TAXIICollectionSink(collection)


class TAXIICollectionSink(DataSink):
    """
    """
    def __init__(self, collection, name="TAXIICollectionSink"):
        super(TAXIICollectionSink, self).__init__(name=name)
        self.collection = collection

    def add(self, stix_obj):
        """
        """
        self.collection.add_objects(self.create_bundle([json.loads(str(stix_obj))]))

    @staticmethod
    def create_bundle(objects):
        return dict(id="bundle--%s" % make_id(),
                    objects=objects,
                    spec_version="2.0",
                    type="bundle")


class TAXIICollectionSource(DataSource):
    """
    """
    def __init__(self, collection, name="TAXIICollectionSource"):
        super(TAXIICollectionSource, self).__init__(name=name)
        self.collection = collection

    def get(self, stix_id, _composite_filters=None):
        """
        """
        # combine all query filters
        query = []
        if self.filters:
            query.extend(self.filters.values())
        if _composite_filters:
            query.extend(_composite_filters)

        # separate taxii query terms (can be done remotely)
        taxii_filters = self._parse_taxii_filters(query)

        stix_objs = self.collection.get_object(stix_id, taxii_filters)["objects"]

        stix_obj = self.apply_common_filters(stix_objs, query)

        if len(stix_obj) > 0:
            stix_obj = stix_obj[0]
        else:
            stix_obj = None

        return stix_obj

    def all_versions(self, stix_id, _composite_filters=None):
        """
        """
        # make query in TAXII query format since 'id' is TAXII field
        query = [
            {
                "field": "match[id]",
                "op": "=",
                "value": stix_id
            },
            {
                "field": "match[version]",
                "op": "=",
                "value": "all"
            }
        ]

        all_data = self.query(query=query, _composite_filters=_composite_filters)

        return all_data

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

        # separate taxii query terms (can be done remotely)
        taxii_filters = self._parse_taxii_filters(query)

        # query TAXII collection
        all_data = self.collection.get_objects(filters=taxii_filters)["objects"]

        # deduplicate data (before filtering as reduces wasted filtering)
        all_data = self.deduplicate(all_data)

        # apply local (composite and data source filters)
        all_data = self.apply_common_filters(all_data, query)

        return all_data

    def _parse_taxii_filters(self, query):
        """Parse out TAXII filters that the TAXII server can filter on.

        Notes:
            For instance - "?match[type]=indicator,sighting" should be in a
            query dict as follows:

            {
                "field": "type"
                "op": "=",
                "value": "indicator,sighting"
            }

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
