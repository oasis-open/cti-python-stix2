import datetime as dt

import pytz

import stix2
from stix2.datastore.relational_db.relational_db import RelationalDBSink

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
    ref = stix2.v21.ExternalReference(
        source_name="veris",
        external_id="0001AA7F-C601-424A-B2B8-BE6C9F5164E7",
        # hashes={
        #    "SHA-256": "6db12788c37247f2316052e142f42f4b259d6561751e5f401a1ae2a6df9c674b",
        # },
        url="https://github.com/vz-risk/VCDB/blob/master/data/json/0001AA7F-C601-424A-B2B8-BE6C9F5164E7.json",
    )
    now = dt.datetime(2016, 5, 12, 8, 17, 27, tzinfo=pytz.utc)

    malware = stix2.v21.Malware(
        external_references=[ref],
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


def main():
    store = RelationalDBSink("postgresql://localhost/stix-data-sink")
    store.generate_stix_schema()


if __name__ == '__main__':
    main()
