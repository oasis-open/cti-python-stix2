import json

from py2neo import Graph, Node, Relationship

import stix2
from stix2.base import _STIXBase
from stix2.datastore import (
    DataSink, DataSource, DataStoreMixin,
)
from stix2.parsing import parse


def remove_sro_from_list(sro, sro_list):
    for rel in sro_list:
        if (rel["source_ref"] == sro["source_ref"] and
                rel["target_ref"] == sro["target_ref"] and
                    rel["relationship_type"] == sro["relationship_type"]):
            sro_list.remove(rel)
            break
    return sro_list


def hash_dict_as_string(hash_dict):
    hashes = []
    for hash_type, hash in hash_dict.items():
        hashes.append(f'{hash_type}:{hash}')
    return ",".join(hashes)

def _add(sink, stix_data, allow_custom=True, version="2.1"):
    """Add STIX objects to MemoryStore/Sink.

    Adds STIX objects to an in-memory dictionary for fast lookup.
    Recursive function, breaks down STIX Bundles and lists.

    Args:
        store: A MemoryStore, MemorySink or MemorySource object.
        stix_data (list OR dict OR STIX object): STIX objects to be added
        allow_custom (bool): Whether to allow custom properties as well unknown
            custom objects. Note that unknown custom objects cannot be parsed
            into STIX objects, and will be returned as is. Default: False.
        version (str): Which STIX2 version to lock the parser to. (e.g. "2.0",
            "2.1"). If None, the library makes the best effort to figure
            out the spec representation of the object.

    """
    if isinstance(stix_data, list):
        # STIX objects are in a list- recurse on each object
        for stix_obj in stix_data:
            _add(sink, stix_obj, allow_custom, version)

    elif stix_data["type"] == "bundle":
        # adding a json bundle - so just grab STIX objects
        for stix_obj in stix_data.get("objects", []):
            _add(sink, stix_obj, allow_custom, version)

    else:
        # Adding a single non-bundle object
        if isinstance(stix_data, _STIXBase):
            stix_obj = stix_data
        else:
            stix_obj = parse(stix_data, allow_custom, version)

        sink.insert_object(stix_obj)


class Neo4jStore(DataStoreMixin):
    default_host = "localhost"
    default_username = "neo4j"
    default_password = "password"

    default_neo4j_connection = "bolt://neo4j:password@localhost:7687"

    def __init__(self, host=default_host, username=default_username, password=default_password, allow_custom=True, version=None,
                 clear_database=True):
        self.sgraph = Graph(host=host, auth=(username, password))
        super().__init__(
            source = Neo4jSource(
                sgraph=self.sgraph,
                allow_custom=allow_custom,

            ),
            sink = Neo4jSink(
                sgraph=self.sgraph,
                allow_custom=allow_custom,
                version=version,
                clear_database=clear_database,


            )
        )


class Neo4jSource(DataSource):
    def __init__(self, sgraph, allow_custom):
        pass

    def all_versions(self, stix_id):
        pass

    def query(self, query=None):
        pass

    def get(self, stix_id):
        pass


class Neo4jSink(DataSink):

    def add(self, stix_data, version=None):
        _add(self, stix_data, self.allow_custom)
    add.__doc__ = _add.__doc__

    def __init__(self, sgraph, allow_custom=True, version=None, clear_database=False):
        super(Neo4jSink, self).__init__()
        self.sgraph = sgraph
        self.relationships_to_recheck = list()
        self.sub_object_relationships = list()
        self.counter = 1
        self.allow_custom=allow_custom
        if clear_database:
            self.sgraph.delete_all()

    def insert_object(self, obj):
        # need something better to check for sros, this will not handle sightings
        if obj["type"] == "relationship":
            self._insert_sro(obj)
        else:
            self._insert_sdo_sco_smo(obj, obj["type"])

    def next_id(self):
        self.counter += 1
        return str(self.counter)

    def _insert_sdo_sco_smo(self, obj, type_name):
        extension_relationships = list()
        self.sub_object_relationships = list()
        external_references = list()
        keys = obj.keys()
        node_contents = dict()
        # If the SCO does not have a name field, use the type as name
        if 'name' not in keys:
            node_name = obj["type"] + "_" + self.next_id()
        else:
            node_name = obj["name"]
        # add id and type to node contents
        if "id" in obj:
            node_contents["id"] = obj["id"]
        node_contents["type"] = type_name
        # store rest of object contents in node contents
        for key in keys:
            if key not in ["type", "name", "id"] and not key.endswith("ref") and not key.endswith("refs"):
                # collections not allowed as neo4j property value
                # convert nested collections to string
                if isinstance(obj[key], list):
                    if isinstance(obj[key][0], str):
                        node_contents[key] = ",".join(obj[key])
                    elif isinstance(obj[key][0], stix2.ExternalReference):
                        external_references = obj[key]
                    else:
                        print(obj[key])
                elif not isinstance(obj[key], dict):
                    node_contents[key] = obj[key]
                elif key == "hashes":
                    node_contents[key] = hash_dict_as_string(obj[key])
                elif key == "extensions":
                    for extension_id, value in obj[key].items():
                        if hasattr(value, "extension_type") and value.extension_type and value.extension_type.startswith("new-"):
                            continue
                        else:
                            extension_relationships.append(value)
                else:
                    self.sub_object_relationships.append((key, obj[key]))
        # Make the Bundle ID a property
        # use dictionary expansion as keyword for optional node properties
        node = Node(type_name,
                    name=node_name,
                    # bundlesource=self.bundlename,
                    **node_contents)
        # if node needs new created_by relation, create the node and then the relationship
        self.sgraph.create(node)
        # check to see if the addition of this node makes it possible to create a relationship
        for rel in self.relationships_to_recheck:
            self._insert_sro(rel, True)
        self._insert_embedded_relationships(obj, obj["id"])
        self._insert_external_references(external_references, node)
        self._insert_extensions(extension_relationships, node)
        self._insert_sub_objects(self.sub_object_relationships, node)

    def _insert_sub_object(self, sub_prop, sub_obj, parent_node):
        node_contents = dict()
        node_contents["type"] = sub_prop
        for key, value in sub_obj.items():
            if not key.endswith("ref") and not key.endswith("refs"):
                if isinstance(value, list):
                    if isinstance(value[0], str):
                        node_contents[key] = ",".join(value)
                    elif isinstance(value[0], dict):
                        for v in value:
                            self.sub_object_relationships.append((key, v))
                elif key == "hashes":
                    node_contents[key] = hash_dict_as_string(value)
                elif not isinstance(value, dict):
                    node_contents[key] = value
                else:
                    self.sub_object_relationships.append((key, value))
        node = Node(sub_prop,
                    name=sub_prop + "_" + self.next_id(),
                    # bundlesource=self.bundlename,
                    **node_contents)
        self.sgraph.create(node)
        relationship = Relationship(parent_node, sub_prop, node)
        self.sgraph.create(relationship)
        self._insert_embedded_relationships(sub_obj, parent_node["id"])

    def _insert_sub_objects(self, sub_objects, parent_node):
        for sub in sub_objects:
            self._insert_sub_object(sub[0], sub[1], parent_node)

    def _insert_external_references(self, refs, parent_node):
        for ref in refs:
            node_contents = dict()
            node_contents["type"] = "external_reference"
            for key, value in ref.items():
                if key == "hashes":
                    node_contents[key] = hash_dict_as_string(value)
                elif not isinstance(value, dict):
                    node_contents[key] = value
                else:
                    self.sub_object_relationships.append((key, value))
            node = Node("external_reference",
                        name="external_reference" + "_" + self.next_id(),
                        # bundlesource=self.bundlename,
                        **node_contents)
            relationship = Relationship(parent_node, "external_reference", node)
            self.sgraph.create(relationship)

    def _insert_extensions(self, extensions, parent_node):
        for ext in extensions:
            node_contents = dict()
            type_name = ext.__class__.__name__
            node_contents["type"] = type_name
            for key, value in ext.items():
                if not key.endswith("ref") and not key.endswith("refs"):
                    if isinstance(value, list):
                        if isinstance(value[0], str):
                            node_contents[key] = ",".join(value)
                        else:
                            for v in value:
                                self.sub_object_relationships.append((key, v))
                    elif key == "hashes":
                        node_contents[key] = hash_dict_as_string(value)
                    else:
                        node_contents[key] = value
            node = Node(type_name,
                        name=type_name + "_" + self.next_id(),
                        # bundlesource=self.bundlename,
                        **node_contents)
            relationship = Relationship(parent_node, type_name, node)
            self.sgraph.create(relationship)
            self._insert_embedded_relationships(ext, parent_node["id"])

    def _is_node_available(self, id,):
        cypher_string = f'OPTIONAL MATCH (a) WHERE a.id="{str(id)}" UNWIND [a] AS list_rows RETURN list_rows'
        cursor = self.sgraph.run(cypher_string).data()
        return cursor[0]["list_rows"]

    def _insert_sro(self, obj, recheck=False):
        reltype = str(obj['relationship_type'])
        # Fix Relationships with hyphens, neo4j will throw syntax error as
        # the hyphen is interpreted as an operation in the query string
        reltype = reltype.replace('-', '_')
        # create the relationship
        # query for the existence of both source and target objects
        # save ones for which both don't exist, and check the list whenever a new S(D|C|M)O is added
        if self._is_node_available(obj["source_ref"]) and self._is_node_available(obj["target_ref"]):
            cypher_string = f'MATCH (a),(b) WHERE a.id="{str(obj["source_ref"])}" AND b.id="{str(obj["target_ref"])}" CREATE (a)-[r:{reltype}]->(b) RETURN a,b'
            self.sgraph.run(cypher_string)
            print(f'Created {str(obj["source_ref"])} {reltype} {obj["target_ref"]}')
            if recheck:
                remove_sro_from_list(obj, self.relationships_to_recheck)
        else:
            if not recheck:
                self.relationships_to_recheck.append(obj)

    def _insert_embedded_relationships(self, obj, id, recheck=False):
        for k in obj.keys():
            k_tokens = k.split("_")
            # find refs, but ignore external_references since they aren't objects
            if "ref" in k_tokens[len(k_tokens) - 1] and k_tokens[len(k_tokens) - 1] != "references":
                rel_type = "_".join(k_tokens[: -1])
                ref_list = []
                # refs are lists, push singular ref into list to make it iterable for loop
                if not type(obj[k]).__name__ == "list":
                    ref_list.append(obj[k])
                else:
                    ref_list = obj[k]
                for ref in ref_list:
                    if self._is_node_available(ref):
                        # The "b to a" relationship is reversed in this cypher query to ensure the correct relationship direction in the graph
                        cypher_string = f'MATCH (a),(b) WHERE a.id="{str(ref)}" AND b.id="{str(id)}" CREATE (b)-[r:{k}]->(a) RETURN a,b'
                        self.sgraph.run(cypher_string)
                        print(f'Created * {str(id)} {k} {str(ref)}')
                        if recheck:
                            remove_sro_from_list(obj, self.relationships_to_recheck)
                    else:
                        if not recheck:
                            embedded_relationship = {"source_ref": id,
                                                     "target_ref": ref,
                                                     "relationship_type": k}
                            self.relationships_to_recheck.append(embedded_relationship)


