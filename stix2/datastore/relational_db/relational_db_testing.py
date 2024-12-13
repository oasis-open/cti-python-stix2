import datetime as dt
import os  # noqa: F401

from database_backends.mariadb_backend import MariaDBBackend  # noqa: F401
from database_backends.postgres_backend import PostgresBackend  # noqa: F401
from database_backends.sqlite_backend import SQLiteBackend
import pytz

import stix2
from stix2.datastore.relational_db.relational_db import RelationalDBStore
import stix2.properties

email_message = stix2.EmailMessage(
                    type="email-message",
                    spec_version="2.1",
                    id="email-message--0c57a381-2a17-5e61-8754-5ef96efb286c",
                    from_ref="email-addr--9b7e29b3-fd8d-562e-b3f0-8fc8134f5dda",
                    to_refs=["email-addr--d1b3bf0c-f02a-51a1-8102-11aba7959868"],
                    is_multipart=False,
                    date="2004-05-19T12:22:23.000Z",
                    subject="Did you see this?",
                    additional_header_fields={
                        "Reply-To": [
                            "steve@example.com",
                            "jane@example.com",
                        ],
                    },
)

directory_stix_object = stix2.Directory(
    path="/foo/bar/a",
    path_enc="latin1",
    ctime="1980-02-23T05:43:28.2678Z",
    atime="1991-06-09T18:06:33.915Z",
    mtime="2000-06-28T13:06:09.5827Z",
    contains_refs=[
        "file--8903b558-40e3-43e2-be90-b341c12ff7ae",
        "directory--e0604d0c-bab3-4487-b350-87ac1a3a195c",
    ],
    object_marking_refs=[
        "marking-definition--1b3eec29-5376-4837-bd93-73203e65d73c",
    ],
)

s = stix2.v21.Software(
    id="software--28897173-7314-4eec-b1cf-2c625b635bf6",
    name="Word",
    cpe="cpe:2.3:a:microsoft:word:2000:*:*:*:*:*:*:*",
    swid="com.acme.rms-ce-v4-1-5-0",
    version="2002",
    languages=["c", "lisp"],
    vendor="Microsoft",
)


def windows_registry_key_example():
    v1 = stix2.v21.WindowsRegistryValueType(
        name="Foo",
        data="qwerty",
        data_type="REG_SZ",
    )
    v2 = stix2.v21.WindowsRegistryValueType(
        name="Bar",
        data="Fred",
        data_type="REG_SZ",
    )
    w = stix2.v21.WindowsRegistryKey(
        key="hkey_local_machine\\system\\bar\\foo",
        values=[v1, v2],
    )
    return w


def malware_with_all_required_properties():
    ref1 = stix2.v21.ExternalReference(
        source_name="veris",
        external_id="0001AA7F-C601-424A-B2B8-BE6C9F5164E7",
        hashes={
           "SHA-256": "6db12788c37247f2316052e142f42f4b259d6561751e5f401a1ae2a6df9c674b",
           "MD5":  "3773a88f65a5e780c8dff9cdc3a056f3",
        },
        url="https://github.com/vz-risk/VCDB/blob/master/data/json/0001AA7F-C601-424A-B2B8-BE6C9F5164E7.json",
    )
    ref2 = stix2.v21.ExternalReference(
        source_name="ACME Threat Intel",
        description="Threat report",
        url="http://www.example.com/threat-report.pdf",
    )
    now = dt.datetime(2016, 5, 12, 8, 17, 27, tzinfo=pytz.utc)

    malware = stix2.v21.Malware(
        external_references=[ref1, ref2],
        type="malware",
        id="malware--9c4638ec-f1de-4ddb-abf4-1b760417654e",
        created=now,
        modified=now,
        name="Cryptolocker",
        is_family=False,
        labels=["foo", "bar"],
    )
    return malware


def file_example_with_PDFExt_Object():
    f = stix2.v21.File(
        name="qwerty.dll",
        magic_number_hex="504B0304",
        extensions={
            "pdf-ext": stix2.v21.PDFExt(
                version="1.7",
                document_info_dict={
                    "Title": "Sample document",
                    "Author": "Adobe Systems Incorporated",
                    "Creator": "Adobe FrameMaker 5.5.3 for Power Macintosh",
                    "Producer": "Acrobat Distiller 3.01 for Power Macintosh",
                    "CreationDate": "20070412090123-02",
                },
                pdfid0="DFCE52BD827ECF765649852119D",
                pdfid1="57A1E0F9ED2AE523E313C",
            ),
        },
    )
    return f


def extension_definition_insert():
    return stix2.ExtensionDefinition(
        created_by_ref="identity--8a5fb7e4-aabe-4635-8972-cbcde1fa4792",
        name="test",
        schema="a schema",
        version="1.2.3",
        extension_types=["property-extension", "new-sdo", "new-sro"],
        object_marking_refs=[
            "marking-definition--caa0d913-5db8-4424-aae0-43e770287d30",
            "marking-definition--122a27a0-b96f-46bc-8fcd-f7a159757e77",
        ],
        granular_markings=[
            {
                "lang": "en_US",
                "selectors": ["name", "schema"],
            },
            {
                "marking_ref": "marking-definition--50902d70-37ae-4f85-af68-3f4095493b42",
                "selectors": ["name", "schema"],
            },
        ],
    )


def dictionary_test():
    return stix2.File(
        spec_version="2.1",
        name="picture.jpg",
        defanged=True,
        ctime="1980-02-23T05:43:28.2678Z",
        extensions={
            "raster-image-ext": {
                "exif_tags": {
                    "Make": "Nikon",
                    "Model": "D7000",
                    "XResolution": 4928,
                    "YResolution": 3264,
                },
            },
        },
    )


def kill_chain_test():
    return stix2.AttackPattern(
        spec_version="2.1",
        id="attack-pattern--0c7b5b88-8ff7-4a4d-aa9d-feb398cd0061",
        created="2016-05-12T08:17:27.000Z",
        modified="2016-05-12T08:17:27.000Z",
        name="Spear Phishing",
        kill_chain_phases=[
            {
                "kill_chain_name": "lockheed-martin-cyber-kill-chain",
                "phase_name": "reconnaissance",
            },
        ],
        external_references=[
            {
                "source_name": "capec",
                "external_id": "CAPEC-163",
            },
        ],
        granular_markings=[
            {
                "lang": "en_US",
                "selectors": ["kill_chain_phases"],
            },
            {
                "marking_ref": "marking-definition--50902d70-37ae-4f85-af68-3f4095493b42",
                "selectors": ["external_references"],
            },
        ], )


@stix2.CustomObject(
    'x-custom-type',
    properties=[
        ("phases", stix2.properties.ListProperty(stix2.KillChainPhase)),
        ("something_else", stix2.properties.IntegerProperty()),
    ],
)
class CustomClass:
    pass


def custom_obj():
    obj = CustomClass(
        phases=[
            {
                "kill_chain_name": "chain name",
                "phase_name": "the phase name",
            },
        ],
        something_else=5,
    )
    return obj


@stix2.CustomObject(
    "test-object", [
        ("prop_name", stix2.properties.ListProperty(stix2.properties.BinaryProperty())),
    ],
    "extension-definition--15de9cdb-3515-4271-8479-8141154c5647",
    is_sdo=True,
)
class TestClass:
    pass


def test_binary_list():
    return TestClass(prop_name=["AREi", "7t3M"])


@stix2.CustomObject(
        "test2-object", [
            (
                "prop_name", stix2.properties.ListProperty(
                    stix2.properties.HexProperty(),
                ),
            ),
        ],
        "extension-definition--15de9cdb-4567-4271-8479-8141154c5647",
        is_sdo=True,
)
class Test2Class:
    pass


def test_hex_list():
    return Test2Class(
        prop_name=["1122", "fedc"],
    )


@stix2.CustomObject(
        "test3-object", [
            (
                "prop_name",
                stix2.properties.DictionaryProperty(
                    valid_types=[
                        stix2.properties.IntegerProperty,
                        stix2.properties.FloatProperty,
                        stix2.properties.StringProperty,
                    ],
                ),
            ),
            (
                "list_of_timestamps",
                stix2.properties.ListProperty(stix2.properties.TimestampProperty()),
            ),
        ],
        "extension-definition--15de9cdb-1234-4271-8479-8141154c5647",
        is_sdo=True,
)
class Test3Class:
    pass


def test_dictionary():
    return Test3Class(
        prop_name={"a": 1, "b": 2.3, "c": "foo"},
        list_of_timestamps=["2016-05-12T08:17:27.000Z", "2024-05-12T08:17:27.000Z"],
    )


def main():
    store = RelationalDBStore(
        # MariaDBBackend(f"mariadb+pymysql://admin:admin@127.0.0.1:3306/rdb", force_recreate=True),
        # PostgresBackend("postgresql://localhost/stix-data-sink", force_recreate=True),
        SQLiteBackend("sqlite:///stix-data-sink.db", force_recreate=True),

        True,
        None,
        True,
        print_sql=True,
    )

    if store.sink.db_backend.database_exists:

        ap = kill_chain_test()
        store.add(ap)

        x = email_message

        store.add(x)

        td = test_dictionary()

        store.add(td)

        th = test_hex_list()

        store.add(th)

        tb = test_binary_list()

        store.add(tb)

        co = custom_obj()

        store.add(co)

        pdf_file = file_example_with_PDFExt_Object()
        store.add(pdf_file)

        store.add(directory_stix_object)

        store.add(s)

        store.add(extension_definition_insert())

        dict_example = dictionary_test()
        store.add(dict_example)

        malware = malware_with_all_required_properties()
        store.add(malware)

        # read_obj = store.get(directory_stix_object.id)
        # print(read_obj)
    else:
        print("database does not exist")


if __name__ == '__main__':
    main()
