"""
Python STIX 2.0 TAXII Source/Sink

Classes:
    TAXIICollectionStore
    TAXIICollectionSink
    TAXIICollectionSource

TODO: Test everything

"""

import json
import uuid

from stix2.sources import DataSink, DataSource, DataStore, make_id

TAXII_FILTERS = ['added_after', 'id', 'type', 'version']


class TAXIICollectionStore(DataStore):
    """
    """
    def __init__(self,
                 taxii_client=None,
                 api_root_name=None,
                 collection_id=None,
                 user=None,
                 password=None,
                 name="TAXIICollectionStore"):

        self.name = name
        self.id = make_id()
        self.source = TAXIICollectionSource(taxii_client, api_root_name, collection_id, user, password)
        self.sink = self.TAXIICollectionSink(taxii_client, api_root_name, collection_id, user, password)

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


class TAXIICollectionSink(DataSink):
    """
    """

    def __init__(self, taxii_client=None, api_root_name=None, collection_id=None, user=None, password=None, name="TAXIICollectionSink"):
        super(TAXIICollectionSink, self).__init__(name=name)

        self.taxii_client = taxii_client
        self.taxii_client.populate_available_information()

        if not api_root_name:
            raise ValueError("No api_root specified.")
        else:
            self.api_root = None
            for a_r in self.taxii_client.api_roots:
                if api_root_name == a_r.name:
                    self.api_root = a_r
                    break
            if not self.api_root:
                raise ValueError("The api_root %s is not found on this taxii server" % api_root_name)
        if not collection_id:
            raise ValueError("No collection specified.")
        else:
            self.collection = None
            for c in self.api_root.collections:
                if c.id_ == collection_id:
                    self.collection = c
                    break
            if not self.collection:
                raise ValueError("The collection %s is not found on the api_root %s of this taxii server" %
                                 (collection_id, api_root_name))

    def add(self, stix_obj):
        """
        """
        self.collection.add_objects(self.create_bundle([json.loads(str(stix_obj))]))

    @staticmethod
    def create_bundle(objects):
        return dict(id="bundle--" + str(uuid.uuid4()),
                    objects=objects,
                    spec_version="2.0",
                    type="bundle")

    # utility functions for the current set collection and api root
    def get_api_root_info(self):
        """
        """
        return self.api_root.get_information()

    def get_api_root_collections(self):
        """
        """
        return self.api_root.get_collections()

    def get_collection_manifest(self):
        """
        """
        return self.collection.get_collection_manifest()


class TAXIICollectionSource(DataSource):
    """
    """
    def __init__(self, taxii_client=None, api_root_name=None, collection_id=None, user=None, password=None, name="TAXIICollectionSourc"):
        super(TAXIICollectionSource, self).__init__(name=name)

        self.taxii_client = taxii_client
        self.taxii_client.populate_available_information()

        if not api_root_name:
            raise ValueError("No api_root specified.")
        else:
            self.api_root = None
            for a_r in self.taxii_client.api_roots:
                if api_root_name == a_r.name:
                    self.api_root = a_r
                    break
            if not self.api_root:
                raise ValueError("The api_root %s is not found on this taxii server" % api_root_name)
        if not collection_id:
            raise ValueError("No collection specified.")
        else:
            self.collection = None
            for c in self.api_root.collections:
                if c.id_ == collection_id:
                    self.collection = c
                    break
            if not self.collection:
                raise ValueError("The collection %s is not found on the api_root %s of this taxii server" %
                                 (collection_id, api_root_name))

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
        """Parse out TAXII filters that the TAXII server can filter on

         For instance
        "?match[type]=indicator,sighting" should be in a query dict as follows
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
            if filter_["field"] in TAXII_FILTERS:
                if filter_["field"] == "added_after":
                    params[filter_["field"]] = filter_["value"]
                else:
                    taxii_field = "match[" + filter_["field"] + ']'
                    params[taxii_field] = filter_["value"]
        return params

    # utility functions for the current attached collection and api root
    def get_api_root_info(self):
        """
        """
        return self.api_root.get_information()

    def get_api_root_collections(self):
        """
        """
        return self.api_root.get_collections()

    def get_collection_manifest(self):
        """
        """
        return self.collection.get_collection_manifest()


def get_server_api_roots(taxii_client):
    """
    """
    api_root_info = []
    taxii_client.populate_available_information()

    for api_root in taxii_client.api_roots:
        api_root_info.append(api_root.information())

    return api_root_info


def get_server_collections(taxii_client):
    """
    """
    server_collections = []

    taxii_client.populate_available_information()

    for api_root in taxii_client.api_roots:
        server_collections.extend(api_root.get_collections())

    return server_collections


def get_api_root_collections(taxii_client, api_root_name):
    """
    """
    taxii_client.populate_available_information()

    for api_root in taxii_client.api_roots:
        if api_root == api_root_name:
            return api_root.get_collections()
