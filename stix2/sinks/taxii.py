import json
import uuid

from stix2.sinks import DataSink
from taxii2_client import TAXII2Client


class TAXIIDataSink(DataSink):
    """STIX 2.0 Data Source - TAXII 2.0 module"""

    def __init__(self, taxii_client=None, server_uri=None, api_root_name=None, collection_id=None, user=None, password=None, name="TAXII"):

        if taxii_client and server_uri:
            raise ValueError("TAXIIDataSink takes either a taxii_client or a server_uri, but not both")
        if taxii_client:
            self.taxii_client = taxii_client
        elif server_uri:
            self.taxii_client = TAXII2Client(server_uri, user, password)

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

        super(TAXIIDataSink, self).__init__(name="/".join([self.taxii_client.server_uri,
                                                           self.api_root.name,
                                                           "collections",
                                                           self.collection.id_]))

    @staticmethod
    def create_bundle(objects):
        return dict(id="bundle--" + str(uuid.uuid4()),
                    objects=objects,
                    spec_version="2.0",
                    type="bundle")

    def save(self, obj):
        self.collection.add_objects(self.create_bundle([json.loads(str(obj))]))

    def close(self):
        """Close down the Data Source - if any clean up is required.
        """
        pass
