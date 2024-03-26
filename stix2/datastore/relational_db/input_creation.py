from collections import OrderedDict

from sqlalchemy import insert

from stix2.datastore.relational_db.utils import (
    SCO_COMMON_PROPERTIES, SDO_COMMON_PROPERTIES, canonicalize_table_name,
)
from stix2.properties import (
    DictionaryProperty, EmbeddedObjectProperty, EnumProperty,
    ExtensionsProperty, FloatProperty, IntegerProperty, ListProperty,
    ReferenceProperty, StringProperty,
)


def single_value(p):
    return not isinstance(
        p, (
            EmbeddedObjectProperty,
            ListProperty,
            DictionaryProperty,
        ),
    )


def table_property(prop, name, core_properties):
    if isinstance(prop, ListProperty) and name not in core_properties:
        contained_property = prop.contained
        return not isinstance(contained_property, (StringProperty, IntegerProperty, FloatProperty))
    elif isinstance(prop, DictionaryProperty) and name not in core_properties:
        return True
    else:
        return False


def embedded_object_list_property(prop, name, core_properties):
    if isinstance(prop, ListProperty) and name not in core_properties:
        contained_property = prop.contained
        return isinstance(contained_property, EmbeddedObjectProperty)
    else:
        return False


def array_property(prop, name, core_properties):
    if isinstance(prop, ListProperty) and name not in core_properties:
        contained_property = prop.contained
        return isinstance(contained_property, (StringProperty, IntegerProperty, FloatProperty, EnumProperty))
    else:
        return False


def derive_column_name(prop):
    contained_property = prop.contained
    if isinstance(contained_property, ReferenceProperty):
        return "ref_id"
    elif isinstance(contained_property, StringProperty):
        return "value"


def generate_insert_for_array_in_table(table, values, foreign_key_value):

    bindings = {
        "id": foreign_key_value,
    }

    for idx, item in enumerate(values):
        item_binding_name = f"item{idx}"

        bindings[item_binding_name] = item

    return [insert(table).values(bindings)]


def generate_single_values(stix_object, properties, core_properties=[]):
    bindings = OrderedDict()
    for name, prop in properties.items():
        if (
            single_value(prop) and (name == 'id' or name not in core_properties) or
            array_property(prop, name, core_properties)
        ):
            if name in stix_object and name != "type":
                bindings[name] = stix_object[name] if not array_property(prop, name, core_properties) else "{" + ",".join(
                    ['"' + x + '"' for x in stix_object[name]],
                ) + "}"
    return bindings


def generate_insert_for_embedded_object(type_name, item, foreign_key_value):
    bindings = generate_single_values(item, item._properties)
    bindings["id"] = foreign_key_value


def generate_insert_for_dictionary(item, dictionary_table, foreign_key_value, value_types):
    bindings = {"id": foreign_key_value}

    for idx, (name, value) in enumerate(item.items()):
        name_binding = f"name{idx}"
        if len(value_types) == 1:
            value_binding = f"value{idx}"
        elif isinstance(value, int):
            value_binding = f"integer_value{idx}"
        else:
            value_binding = f"string_value{idx}"

        bindings[name_binding] = name
        bindings[value_binding] = value

        return [insert(dictionary_table).values(bindings)]


def generate_insert_for_embedded_objects(type_name, values, foreign_key_value):
    sql_bindings_tuples = list()
    for item in values:
        sql_bindings_tuples.extend(generate_insert_for_embedded_object(type_name, item, foreign_key_value))
    return sql_bindings_tuples


def generate_insert_for_hashes(hashes, hashes_table, foreign_key_value):
    bindings = {"id": foreign_key_value}

    for idx, (hash_name, hash_value) in enumerate(hashes.items()):
        hash_name_binding_name = "hash_name" + str(idx)
        hash_value_binding_name = "hash_value" + str(idx)

        bindings[hash_name_binding_name] = hash_name
        bindings[hash_value_binding_name] = hash_value

    return [insert(hashes_table).values(bindings)]


def generate_insert_for_external_references(data_sink, stix_object):
    insert_statements = list()
    object_table = data_sink.tables_dictionary["common.external_references"]
    for er in stix_object["external_references"]:
        bindings = {"id": stix_object["id"]}
        for prop in ["source_name", "description", "url", "external_id"]:
            if prop in er:
                bindings[prop] = er[prop]
        er_insert_statement = insert(object_table).values(bindings)
        insert_statements.append(er_insert_statement)

        if "hashes" in er:
            hashes_table = data_sink.tables_dictionary[canonicalize_table_name("external_references_hashes", "sdo")]
            insert_statements.extend(
                generate_insert_for_hashes(
                    er["hashes"],
                    hashes_table,
                    stix_object["id"],
                ),
            )

    return insert_statements


def generate_insert_for_granular_markings(granular_markings_table, stix_object):
    granular_markings = stix_object["granular_markings"]
    bindings = {
        "id": stix_object["id"],
    }
    for idx, granular_marking in enumerate(granular_markings):
        lang_binding_name = f"lang{idx}"
        marking_ref_binding_name = f"marking_ref{idx}"
        selectors_binding_name = f"selectors{idx}"

        bindings[lang_binding_name] = granular_marking.get("lang")
        bindings[marking_ref_binding_name] = granular_marking.get("marking_ref")
        bindings[selectors_binding_name] = granular_marking.get("selectors")

    return [insert(granular_markings_table).values(bindings)]


# def generate_insert_for_extensions(extensions, foreign_key_value, type_name, core_properties):
#     sql_bindings_tuples = list()
#     for name, ex in extensions.items():
#         sql_bindings_tuples.extend(
#             generate_insert_for_subtype_extension(
#                 name,
#                 ex,
#                 foreign_key_value,
#                 type_name,
#                 core_properties,
#             ),
#         )
#     return sql_bindings_tuples


def generate_insert_for_core(data_sink, stix_object, core_properties, schema_name):
    if schema_name == "sdo":
        core_table = data_sink.tables_dictionary["common.core_sdo"]
    else:
        core_table = data_sink.tables_dictionary["common.core_sco"]
    insert_statements = list()
    core_bindings = {}

    for prop_name, value in stix_object.items():

        if prop_name in core_properties:
            # stored in separate tables, skip here
            if prop_name not in {"object_marking_refs", "granular_markings", "external_references", "type"}:
                core_bindings[prop_name] = value

    core_insert_statement = insert(core_table).values(core_bindings)
    insert_statements.append(core_insert_statement)

    if "object_marking_refs" in stix_object:
        if schema_name == "sdo":
            object_markings_ref_table = data_sink.tables_dictionary["common.object_marking_refs_sdo"]
        else:
            object_markings_ref_table = data_sink.tables_dictionary["common.object_marking_refs_sco"]
        insert_statements.extend(
            generate_insert_for_array_in_table(
                object_markings_ref_table,
                stix_object["object_marking_refs"],
                stix_object["id"],
            ),
        )

    # Granular markings
    if "granular_markings" in stix_object:
        if schema_name == "sdo":
            granular_marking_table = data_sink.tables_dictionary["common.granular_marking_sdo"]
        else:
            granular_marking_table = data_sink.tables_dictionary["common.granular_marking_sco"]
        granular_input_statements = generate_insert_for_granular_markings(
            granular_marking_table,
            stix_object.granular_markings,
        )
        insert_statements.extend(granular_input_statements)

    return insert_statements


def generate_insert_for_object(data_sink, stix_object, schema_name, foreign_key_value=None):
    insert_statements = list()
    stix_id = stix_object["id"]
    if schema_name == "sco":
        core_properties = SCO_COMMON_PROPERTIES
    else:
        core_properties = SDO_COMMON_PROPERTIES
    type_name = stix_object["type"]
    table_name = canonicalize_table_name(type_name, schema_name)
    object_table = data_sink.tables_dictionary[table_name]
    properties = stix_object._properties
    insert_statements.extend(generate_insert_for_core(data_sink, stix_object, core_properties, schema_name))

    bindings = generate_single_values(stix_object, properties, core_properties)
    object_insert_statement = insert(object_table).values(bindings)
    insert_statements.append(object_insert_statement)

    for name, prop in stix_object._properties.items():
        if isinstance(prop, DictionaryProperty) and not name == "extensions":
            dictionary_table_name = canonicalize_table_name(type_name + "_" + name, schema_name)
            dictionary_table = data_sink.tables_dictionary[dictionary_table_name]
            insert_statements.extend(generate_insert_for_dictionary(stix_object[name], dictionary_table, stix_id))

    if "external_references" in stix_object:
        insert_statements.extend(generate_insert_for_external_references(data_sink, stix_object, "sdo"))

    if "extensions" in stix_object:
        for ex in stix_object["extensions"]:
            insert_statements.extend(generate_insert_for_object(data_sink, ex, schema_name, stix_id))
    for name, prop in properties.items():
        if table_property(prop, name, core_properties):
            if name in stix_object:
                if embedded_object_list_property(prop, name, core_properties):
                    insert_statements.extend(
                        generate_insert_for_embedded_objects(
                            name,
                            stix_object[name],
                            stix_object["id"],
                        ),
                    )
                elif isinstance(prop, ExtensionsProperty):
                    pass
                else:
                    insert_statements.extend(
                        generate_insert_for_array_in_table(
                            stix_object["type"],
                            name,
                            stix_object[name],
                            properties[name],
                            stix_object["id"], ),
                    )
    return insert_statements
