import json

from stix2.sources.taxii import TAXIIDataSource

# Flask TAXII server - developmental
ROOT = 'http://localhost:5000'
AUTH = {'user': 'mk', 'pass': 'Pass'}


def main():

    # instantiate TAXII data source
    taxii = TAXIIDataSource(api_root=ROOT, auth=AUTH)

    # get (file watch indicator)
    indicator_fw = taxii.get(id_="indicator--a932fcc6-e032-176c-126f-cb970a5a1ade")
    print("\n\n-------Queried for Indicator - got:")
    print(json.dumps(indicator_fw, indent=4))

    # all versions (file watch indicator - currently only 1. maybe Emmanuelle can add a version)
    indicator_fw_versions = taxii.get(id_="indicator--a932fcc6-e032-176c-126f-cb970a5a1ade")
    print("\n\n------Queried for indicator (all_versions()) - got:")
    print(json.dumps(indicator_fw_versions, indent=4))

    # add TAXII filter (ie filter should be passed to TAXII)
    taxii_filter_ids, status = taxii.add_filter(
        [
            {
                "field": "type",
                "op": "in",
                "value": "malware"
            }
        ])

    print("\n\n-------Added filter:")
    print("Filter ID: {0}".format(taxii_filter_ids[0]))
    print("Filter status: \n")
    print(json.dumps(status, indent=4))
    print("filters: \n")
    print(json.dumps(taxii.get_filters(), indent=4))

    # get() - but with filter attached
    malware = taxii.query()
    print("\n\n\n--------Queried for Malware string (with above filter attached) - got:")
    print(json.dumps(malware, indent=4))

    # remove TAXII filter
    taxii.remove_filter(taxii_filter_ids)
    print("\n\n-------Removed filter(TAXII filter):")
    print("filters: \n")
    print(json.dumps(taxii.get_filters(), indent=4))


if __name__ == "__main__":
    main()
