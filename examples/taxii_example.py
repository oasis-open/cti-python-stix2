from taxii2client.v21 import Collection

import stix2

# This example is based on the medallion server with default_data.json
# See https://github.com/oasis-open/cti-taxii-server for more information


def main():
    collection = Collection(
        "http://127.0.0.1:5000/trustgroup1/collections/91a7b528-80eb-42ed-a74d-c6fbd5a26116/",
        user="admin", password="Password0",
    )

    # instantiate TAXII data source
    taxii = stix2.TAXIICollectionSource(collection)

    # get (url watch indicator)
    indicator_fw = taxii.get("indicator--6770298f-0fd8-471a-ab8c-1c658a46574e")
    print("\n\n-------Queried for Indicator - got:")
    print(indicator_fw.serialize(indent=4))

    # all versions (url watch indicator - currently two)
    indicator_fw_versions = taxii.all_versions("indicator--6770298f-0fd8-471a-ab8c-1c658a46574e")
    print("\n\n------Queried for indicator (all_versions()) - got:")
    for indicator in indicator_fw_versions:
        print(indicator.serialize(indent=4))

    # add TAXII filter (ie filter should be passed to TAXII)
    query_filter = stix2.Filter("type", "in", "malware")

    # query() - but with filter attached. There are no malware objects in this collection
    malwares = taxii.query(query=query_filter)
    print("\n\n\n--------Queried for Malware string (with above filter attached) - got:")
    for malware in malwares:
        print(malware.serialize(indent=4))
    if not malwares:
        print(malwares)


if __name__ == "__main__":
    main()
