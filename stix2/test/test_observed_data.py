import stix2

EXPECTED = """{
    "created": "2016-04-06T19:58:16.000Z",
    "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
    "first_observed": "2015-12-21T19:00:00Z",
    "id": "observed-data--b67d30ff-02ac-498a-92f9-32f845f448cf",
    "last_observed": "2015-12-21T19:00:00Z",
    "modified": "2016-04-06T19:58:16.000Z",
    "number_observed": 50,
    "objects": {
        "0": {
            "type": "file"
        }
    },
    "type": "observed-data"
}"""


def test_observed_data_example():
    observed_data = stix2.ObservedData(
        id="observed-data--b67d30ff-02ac-498a-92f9-32f845f448cf",
        created_by_ref="identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        created="2016-04-06T19:58:16.000Z",
        modified="2016-04-06T19:58:16.000Z",
        first_observed="2015-12-21T19:00:00Z",
        last_observed="2015-12-21T19:00:00Z",
        number_observed=50,
        objects={
            "0": {
              "type": "file",
            },
        },
    )

    assert str(observed_data) == EXPECTED

# TODO: Add other examples
