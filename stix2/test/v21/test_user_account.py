import json

import stix2
from stix2.datastore.relational_db.relational_db import RelationalDBStore
import stix2.properties

user_account_dict = {
    "type": "user-account",
    "spec_version": "2.1",
    "id": "user-account--0d5b424b-93b8-5cd8-ac36-306e1789d63c",
    "user_id": "1001",
    "credential": "password",
    "account_login": "jdoe",
    "account_type": "unix",
    "display_name": "John Doe",
    "is_service_account": False,
    "is_privileged": False,
    "can_escalate_privs": True,
    "is_disabled": False,
    "account_created": "2016-01-20T12:31:12Z",
    "account_expires": "2018-01-20T12:31:12Z",
    "credential_last_changed": "2016-01-20T14:27:43Z",
    "account_first_login": "2016-01-20T14:26:07Z",
    "account_last_login": "2016-07-22T16:08:28Z",
}

store = RelationalDBStore(
    "postgresql://postgres:admin@localhost/postgres",
    False,
    None,
    True,
)


def test_user_account():
    store.sink.generate_stix_schema()
    user_account_stix_object = stix2.parse(user_account_dict)
    store.add(user_account_stix_object)
    read_obj = json.loads(store.get(user_account_stix_object['id']).serialize())

    for attrib in user_account_dict.keys():
        if attrib == "account_created" or attrib == "account_expires" \
                or attrib == "credential_last_changed" or attrib == "account_first_login" \
                or attrib == "account_last_login":
            assert stix2.utils.parse_into_datetime(user_account_dict[attrib]) == stix2.utils.parse_into_datetime(
                read_obj[attrib],
            )
            continue
        assert user_account_dict[attrib] == read_obj[attrib]
