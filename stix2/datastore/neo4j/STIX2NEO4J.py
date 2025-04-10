# Reference implementation python script to load STIX 2.1 bundles into
# Neo4J graph database
# Code developed by JHU/APL - First Draft December 2021

# DISCLAIMER
# The script developed by JHU/APL for the demonstration are not “turn key” and are 
# not safe for deployment without being tailored to production infrastructure. These
# files are not being delivered as software and are not appropriate for direct use on any
# production networks. JHU/APL assumes no liability for the direct use of these files and
# they are provided strictly as a reference implementation. 
#
# NO WARRANTY, NO LIABILITY. THIS MATERIAL IS PROVIDED “AS IS.” JHU/APL MAKES NO
# REPRESENTATION OR WARRANTY WITH RESPECT TO THE PERFORMANCE OF THE MATERIALS, INCLUDING
# THEIR SAFETY, EFFECTIVENESS, OR COMMERCIAL VIABILITY, AND DISCLAIMS ALL WARRANTIES IN
# THE MATERIAL, WHETHER EXPRESS OR IMPLIED, INCLUDING (BUT NOT LIMITED TO) ANY AND ALL
# IMPLIED WARRANTIES OF PERFORMANCE, MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE,
# AND NON-INFRINGEMENT OF INTELLECTUAL PROPERTY OR OTHER THIRD PARTY RIGHTS. ANY USER OF
# THE MATERIAL ASSUMES THE ENTIRE RISK AND LIABILITY FOR USING THE MATERIAL. IN NO EVENT
# SHALL JHU/APL BE LIABLE TO ANY USER OF THE MATERIAL FOR ANY ACTUAL, INDIRECT,
# CONSEQUENTIAL, SPECIAL OR OTHER DAMAGES ARISING FROM THE USE OF, OR INABILITY TO USE,
# THE MATERIAL, INCLUDING, BUT NOT LIMITED TO, ANY DAMAGES FOR LOST PROFITS.

## Import python modules for this script
import json
from typing import List
from py2neo import Graph, Node
from getpass import getpass
from tqdm import tqdm

#Import variables
BundleName = input("Enter the name you want for your bundle: ")
NeoHost = input("Enter the hostname for Neo4j server: ")
NeoUser = input("Neo4j User: ")
NeoPass = getpass("Neo4j Password: ")
JSONFILE = input("Path to STIX JSON: ")

class NeoUploader(object):

    def __init__(self):
        # Connect to neo4j
        self.sgraph = Graph(host=NeoHost, auth=(NeoUser, NeoPass))
        self.relations = list()
        self.relationship_ids = set()
        self.nodes_with_object_ref = list()
        self.nodes = list()
        self.bundlename = BundleName
        self.infer_relation = {"parent_ref": "parent_of",
            "created_by_ref": "created_by",
            "src_ref": "source_of",
            "dst_ref": "destination_of"}
        self.__load_json(JSONFILE)

    def __load_json(self, fd):
        data = None
        with open(fd) as json_file:
            data = json.load(json_file)
        for entry in data["objects"]:
            if entry["type"] == "relationship":
                self.relations.append(entry)
            else:
                self.nodes.append(entry)

    # Make Nodes
    def make_nodes(self):
        total_nodes=len(self.nodes)
        for idx, apobj in tqdm(enumerate(self.nodes), total=total_nodes, desc="Making Nodes", unit="node"):
            keys = apobj.keys()
            node_contents = dict()
            #If the SCO does not have a name field, use the type as name
            if 'name' not in keys:
                node_name = apobj["type"]
            else:
                node_name = apobj["name"]
            # add id and type to node contents
            node_contents["ap_id"] = apobj["id"]
            node_contents["type"] = apobj["type"]
            # store rest of object contents in node contents
            for key in keys:
                if key not in ["type", "name", "id"]:
                    # collections not allowed as neo4j property value
                    # convert nested collections to string
                    if isinstance(apobj[key], list) or isinstance(apobj[key], dict):
                        node_contents[key] = json.dumps(apobj[key])
                    else:
                        node_contents[key] = apobj[key]
            # Make the Bundle ID a property
            # use dictionary expansion as keywork for optional node properties
            node = Node(apobj["type"],
                    name=node_name,
                    bundlesource=self.bundlename,
                    **node_contents)
            # if node needs new created_by relation, create the node and then the relationship
            self.sgraph.create(node)
            # save off these nodes for additional relationship creating
            if 'object_refs' in keys:
                self.nodes_with_object_ref.append(apobj)
    
    # create relationships that exist outside of relationship objects
    # such as Created_by and Parent_Of
    def __make_inferred_relations(self):
        total_nodes=len(self.nodes)
        for idx, apobj in tqdm(enumerate(self.nodes), total=total_nodes, desc="Checking Inferred Relationships", unit="node"):
            for k in apobj.keys():
                k_tokens = k.split("_")
                # find refs, but ignore external_references since they aren't objects
                if "ref" in k_tokens[len(k_tokens) - 1] and k_tokens[len(k_tokens) - 1] != "references":
                    rel_type = "_".join(k_tokens[: -1])
                    ref_list = []
                    # refs are lists, push singular ref into list to make it iterable for loop
                    if not type(apobj[k]).__name__ == "list":
                        ref_list.append(apobj[k])
                    else:
                        ref_list = apobj[k]
                    for ref in ref_list:
                    	# The "b to a" relationship is reversed in this cypher query to ensure the correct relationship direction in the graph 
                        cypher_string = f'MATCH (a),(b) WHERE a.bundlesource="{self.bundlename}" AND b.bundlesource="{self.bundlename}" AND a.ap_id="{str(ref)}" AND b.ap_id="{str(apobj["id"])}" CREATE (b)-[r:{rel_type}]->(a) RETURN a,b'
                        try:
                            self.sgraph.run(cypher_string)
                        except Exception as err:
                            print(err)
                            continue

    # Make Relationships
    def make_relationships(self):
        total_rels=len(self.relations)
        for idx, apobj in tqdm(enumerate(self.relations), total=total_rels, desc="Making Relationships", unit="rel"):
            # Define Relationship Type
            reltype = str(apobj['relationship_type'])
            # Fix Relationships with hyphens, neo4j will throw syntax error as
            # the hyphen is interpreted as an operation in the query string
            reltype = reltype.replace('-', '_')
            # create the relationship
            cypher_string = f'MATCH (a),(b) WHERE a.bundlesource="{self.bundlename}" AND b.bundlesource="{self.bundlename}" AND a.ap_id="{str(apobj["source_ref"])}" AND b.ap_id="{str(apobj["target_ref"])}" CREATE (a)-[r:{reltype}]->(b) RETURN a,b'
            self.sgraph.run(cypher_string)
            # maintain set of object ids that are in relationship objects
            self.relationship_ids.add(str(apobj['source_ref']))
            self.relationship_ids.add(str(apobj['target_ref']))
        self.__make_inferred_relations()

    # run the helper methods to upload bundle to neo4j database
    def upload(self):
        self.make_nodes()
        self.make_relationships()


if __name__ == '__main__':
    uploader = NeoUploader()
    uploader.upload()
