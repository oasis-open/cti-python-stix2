import requests
from requests.auth import HTTPBasicAuth

from stix2.sources import DataSource

# TODO: -Should we make properties for the TAXIIDataSource address and other
# possible variables that are found in "self.taxii_info"


TAXII_FILTERS = ['added_after', 'id', 'type', 'version']

test = True


class TAXIIDataSource(DataSource):
    """STIX 2.0 Data Source - TAXII 2.0 module"""

    def __init__(self, api_root=None, auth=None, name="TAXII"):
        super(TAXIIDataSource, self).__init__(name=name)

        if not api_root:
            api_root = "http://localhost:5000"
        if not auth:
            auth = {"user": "admin", "pass": "taxii"}

        self.taxii_info = {
            "api_root": {
                "url": api_root
            },
            "auth": auth
        }

        if test:
            return

        try:
            # check api-root is reachable/exists and grab api collections
            coll_url = self.taxii_info['api_root']['url'] + "/collections/"
            headers = {}

            resp = requests.get(coll_url,
                                headers=headers,
                                auth=HTTPBasicAuth(self.taxii_info['auth']['user'],
                                                   self.taxii_info['auth']['pass']))
            # TESTING
            # print("\n-------__init__() ----\n")
            # print(resp.text)
            # print("\n")
            # print(resp.status_code)
            # END TESTING

            # raise http error if request returned error code
            resp.raise_for_status()

            resp_json = resp.json()

            try:
                self.taxii_info['api_root']['collections'] = resp_json['collections']
            except KeyError as e:
                if e == "collections":
                    raise
                    # raise type(e), type(e)(e.message +
                    # "To connect to the TAXII collections, the API root
                    # resource must contain a collection endpoint URL.
                    # This was not found in the API root resource received
                    # from the API root" ), sys.exc_info()[2]

        except requests.ConnectionError as e:
            raise
            # raise type(e), type(e)(e.message +
            #     "Attempting to connect to %s" % coll_url)

    def get(self, id_, _composite_filters=None):
        """Get STIX 2.0 object from TAXII source by specified 'id'

        Notes:
            Just pass _composite_filters to the query() as they are applied
            there. de-duplication of results is also done within query()

        Args:
            id_ (str): id of STIX object to retrieve

            _composite_filters (list): filters passed from a Composite Data
                Source (if this data source is attached to one)

        Returns:

        """

        # make query in TAXII query format since 'id' is TAXii field
        query = [
            {
                "field": "match[id]",
                "op": "=",
                "value": id_
            }
        ]

        all_data = self.query(query=query, _composite_filters=_composite_filters)

        # reduce to most recent version
        stix_obj = sorted(all_data, key=lambda k: k['modified'])[0]

        return stix_obj

    def all_versions(self, id_, _composite_filters=None):
        """Get all versions of STIX 2.0 object from TAXII source by
        specified 'id'

        Notes:
            Just passes _composite_filters to the query() as they are applied
            there. de-duplication of results is also done within query()

        Args:
            id_ (str): id of STIX objects to retrieve
            _composite_filters (list): filters passed from a Composite Data
                Source (if this data source is attached to one)

        Returns:
            The query results with filters applied.
        """

        # make query in TAXII query format since 'id' is TAXII field
        query = [
            {
                "field": "match[id]",
                "op": "=",
                "value": id_
            }
        ]

        all_data = self.query(query=query, _composite_filters=_composite_filters)

        return all_data

    def query(self, query=None, _composite_filters=None):
        """Query the TAXII data source for STIX objects matching the query

        The final full query could contain filters from:
            -the current API call
            -Composite Data source filters (that are passed in via
                '_composite_filters')
            -TAXII data source filters that are attached

        TAXII filters ['added_after', 'match[<>]'] are extracted and sent
        to TAXII if they are present

        TODO: Authentication for TAXII

        Args:

            query(list): list of filters (dicts) to search on

            _composite_filters (list): filters passed from a
                Composite Data Source (if this data source is attached to one)

        Returns:


        """

        all_data = []

        if query is None:
            query = []

        # combine all query filters
        if self.filters:
            query += self.filters.values()
        if _composite_filters:
            query += _composite_filters

        # separate taxii query terms (can be done remotely)
        taxii_filters = self._parse_taxii_filters(query)

        # for each collection endpoint - send query request
        for collection in self.taxii_info['api_root']['collections']:

            coll_obj_url = "/".join([self.taxii_info['api_root']['url'],
                                     "collections", str(collection['id']),
                                     "objects"])
            headers = {}
            try:
                resp = requests.get(coll_obj_url,
                                    params=taxii_filters,
                                    headers=headers,
                                    auth=HTTPBasicAuth(self.taxii_info['auth']['user'],
                                                       self.taxii_info['auth']['pass']))
                # TESTING
                # print("\n-------query() ----\n")
                # print("Request that was sent: \n")
                # print(resp.url)
                # print("Response: \n")
                # print(json.dumps(resp.json(),indent=4))
                # print("\n")
                # print(resp.status_code)
                # print("------------------")
                # END TESTING

                # raise http error if request returned error code
                resp.raise_for_status()
                resp_json = resp.json()

                # grab all STIX 2.0 objects in json response
                for stix_obj in resp_json['objects']:
                    all_data.append(stix_obj)

            except requests.exceptions.RequestException as e:
                raise
                # raise type(e), type(e)(e.message +
                # "Attempting to connect to %s" % coll_url)

            # TODO: Is there a way to collect exceptions while carrying
            # on then raise all of them at the end?

        # deduplicate data (before filtering as reduces wasted filtering)
        all_data = self.deduplicate(all_data)

        # apply local (composite and data source filters)
        all_data = self.apply_common_filters(all_data, query)

        return all_data

    def _parse_taxii_filters(self, query):
        """Parse out TAXII filters that the TAXII server can filter on

        TAXII filters should be analgous to how they are supplied
        in the url to the TAXII endpoint. For instance
        "?match[type]=indicator,sighting" should be in a query dict as follows
        {
            "field": "match[type]"
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

        for q in query:
            if q['field'] in TAXII_FILTERS:
                if q['field'] == 'added_after':
                    params[q['field']] = q['value']
                else:
                    taxii_field = 'match[' + q['field'] + ']'
                    params[taxii_field] = q['value']
        return params

    def close(self):
        """Close down the Data Source - if any clean up is required.

        """
        pass

    # TODO: - getters/setters (properties) for TAXII config info
