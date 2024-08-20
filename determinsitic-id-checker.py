import json

import stix2


def main():
    with open("sco-examples-bundle.json", "r", encoding="utf-8") as examples:
        all_examples = json.load(examples)
    for obj in all_examples:
        existing_id = obj["id"]
        del obj["id"]
        stix_obj = stix2.parse(obj)
        print(f"id {existing_id} should be {stix_obj['id']}")


if __name__ == "__main__":
    main()