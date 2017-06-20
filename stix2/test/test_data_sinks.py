import os
import stix2
from stix2.sinks import file, taxii


def test_ds_file_save():
    sink = file.FileDataSink("stix.json", mode="overwrite")
    obj = stix2.Malware(type="malware",
                        id="malware--fedcba98-7654-3210-fedc-ba9876543210",
                        labels=["ransomware"],
                        name="Cryptolocker",)

    sink.save(obj)
    sink.close()
    assert os.path.exists("stix.json")


def test_ds_taxii_save():
    sink = taxii.TAXIIDataSink(server_uri="http://localhost:5000",
                               api_root_name="trustgroup1",
                               collection_id="91a7b528-80eb-42ed-a74d-c6fbd5a26116",
                               auth={"user": "ev", "pass": "Password0"}, )
    obj = stix2.Malware(type="malware",
                        id="malware--fedcba98-7654-3210-fedc-ba9876543210",
                        labels=["ransomware"],
                        name="Cryptolocker",)

    sink.save(obj)
    sink.close()
