from collections import OrderedDict

from stix2.properties import (
    DictionaryProperty, EmbeddedObjectProperty, EnumProperty, ExtensionsProperty, FloatProperty,
    IntegerProperty, ListProperty, ReferenceProperty, StringProperty)

# Helps us know which data goes in core, and which in a type-specific table.
SCO_COMMON_PROPERTIES = {
    "id",
    "type",
    "spec_version",
    "object_marking_refs",
    "granular_markings",
    "defanged"
}

# Helps us know which data goes in core, and which in a type-specific table.
SDO_COMMON_PROPERTIES = {
    "id",
    "type",
    "spec_version",
    "object_marking_refs",
    "granular_markings",
    "defanged",
    "created",
    "modified",
    "created_by_ref",
    "revoked",
    "labels",
    "confidence",
    "lang",
    "external_references"
}


def canonicalize_table_name(schema_name, table_name):
    full_name = schema_name + "." + table_name
    return full_name.replace("-", "_")


def single_value(p):
    return not(isinstance(p, (EmbeddedObjectProperty,
                              ListProperty,
                              DictionaryProperty)))


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


def generate_insert_for_array_in_table(type_name, property_name, values, prop, foreign_key_value):
    table_name = canonicalize_table_name(type_name, property_name)
    bindings = {
        "id": foreign_key_value
    }
    all_rows_placeholders = []

    for idx, item in enumerate(values):
        item_binding_name = f"item{idx}"

        all_rows_placeholders.append([
            f"%(id)s",
            f"%({item_binding_name})s"
        ])

        bindings[item_binding_name] = item

    all_rows_sql = ", ".join(
        "(" + ", ".join(row_placeholders) + ")"
        for row_placeholders in all_rows_placeholders
    )

    sql = f"INSERT INTO {table_name}" \
        f" (id, {derive_column_name(prop)})" \
        f" VALUES {all_rows_sql}"

    print("ARRAY sql (", table_name, "): ", sql, sep="")
    print("table array:", bindings)
    return [(sql, bindings)]


def generate_insert_for_embedded_object(type_name, item, foreign_key_value):
    bindings, values = generate_single_values(item, item._properties)
    bindings["id"] = foreign_key_value
    sql = f"INSERT INTO {canonicalize_table_name(type_name, item._type)}" \
          f" ({','.join(bindings.keys())})" \
          f" VALUES ({','.join(values)}, %(id)s )"

    print("sql:", sql)
    print("embedded:", bindings)
    return [(sql, bindings)]


def generate_insert_for_dictionary_object(type_name, item, prop, foreign_key_value):
    values = []
    bindings = {"id": foreign_key_value}
    dict_placeholder_rows = []

    for idx, (name, value) in enumerate(item.items()):
        name_binding = f"name{idx}"
        value_binding = f"value{idx}"

        dict_placeholder_rows.append([
            "%(id)s",
            f"%({name_binding})s",
            f"%({value_binding})s"
        ])

        bindings[name_binding] = name
        bindings[value_binding] = value

    all_rows_sql = ", ".join(
        "(" + ", ".join(row_placeholders) + ")"
        for row_placeholders in dict_placeholder_rows
    )

    sql = f"INSERT INTO {canonicalize_table_name(type_name, prop)}" \
          " (id, name, value)" \
          f" VALUES {all_rows_sql}"

    print("sql:", sql)

    print("sql:", sql)
    print("dict:", bindings)
    return [(sql, bindings)]


def generate_insert_for_embedded_objects(type_name, values, foreign_key_value):
    sql_bindings_tuples = list()
    for item in values:
        sql_bindings_tuples.extend(generate_insert_for_embedded_object(type_name, item, foreign_key_value))
    return sql_bindings_tuples

def generate_insert_for_external_references(values, foreign_key_value):
    sql_bindings_tuples = list()
    for er in values:
        bindings = {"id": foreign_key_value}
        values = []
        for prop in [ "source_name", "description", "url", "external_id"]:
            if prop in er:
                bindings[prop] = er[prop]
                values.append(f"%({prop})s")

        sql = f"INSERT INTO common.external_reference" \
              f" ({','.join(bindings.keys())})" \
              f" VALUES (%(id)s, {','.join(values)})"

        print("sql:", sql)
        print("er:", bindings)
        sql_bindings_tuples.append((sql, bindings))
        if "hashes" in er:
            sql_bindings_tuples.extend(generate_insert_for_hashes(er["hashes"],
                                                                  "common.hashes",
                                                                  foreign_key_value))
    return sql_bindings_tuples



def generate_single_values(stix_object, properties, core_properties=[]):
    values = []
    bindings = OrderedDict()
    for name, prop in properties.items():
        if (single_value(prop) and (name == 'id' or name not in core_properties) or
                array_property(prop, name, core_properties)):
            if name in stix_object:
                bindings[name] = stix_object[name] if not array_property(prop, name, core_properties) else "{" + ",".join(
                    ['"' + x + '"' for x in stix_object[name]]) + "}"
                values.append(f"%({name})s")
    return bindings, values


def generate_insert_for_object(stix_object, stix_object_sco):
    sql_bindings_tuples = list()
    if stix_object_sco:
        core_properties = SCO_COMMON_PROPERTIES
    else:
        core_properties = SDO_COMMON_PROPERTIES
    type_name = stix_object["type"]
    table_name = canonicalize_table_name(type_name, type_name)
    properties = stix_object._properties
    sql_bindings_tuples.extend(generate_insert_for_core(stix_object, core_properties))

    bindings, values = generate_single_values(stix_object, properties, core_properties)

    sql = f"INSERT INTO {table_name}" \
        f" ({','.join(bindings.keys())})" \
        f" VALUES ({','.join(values)})"
    sql_bindings_tuples.append((sql, bindings))

    print("sql:", sql)
    print("obj:", bindings)

    if "external_references" in stix_object:
        sql_bindings_tuples.extend(generate_insert_for_external_references(stix_object["external_references"],
                                                                           stix_object["id"]))

    for name, prop in properties.items():
        if table_property(prop, name, core_properties):
            if name in stix_object:
                if embedded_object_list_property(prop, name, core_properties):
                    sql_bindings_tuples.extend(generate_insert_for_embedded_objects(stix_object["type"],
                                                                                    stix_object[name],
                                                                                    stix_object["id"]))
                elif isinstance(prop, ExtensionsProperty):
                    pass
                else:
                    sql_bindings_tuples.extend(generate_insert_for_array_in_table(stix_object["type"],
                                                                                  name,
                                                                                  stix_object[name],
                                                                                  properties[name],
                                                                                  stix_object["id"] ))
    return sql_bindings_tuples


def generate_insert_for_hashes(hashes, hashes_table_name, **foreign_key):
    foreign_key_name, foreign_key_value = next(iter(foreign_key.items()))

    bindings = {
        foreign_key_name: foreign_key_value
    }

    all_rows_placeholders = []
    for idx, (hash_name, hash_value) in enumerate(hashes.items()):
        hash_name_binding_name = "hash_name" + str(idx)
        hash_value_binding_name = "hash_value" + str(idx)

        all_rows_placeholders.append([
            f"%({foreign_key_name})s",
            f"%({hash_name_binding_name})s",
            f"%({hash_value_binding_name})s"
        ])

        bindings[hash_name_binding_name] = hash_name
        bindings[hash_value_binding_name] = hash_value

    all_rows_placeholders_sql = ", ".join(
        "(" + ", ".join(row_placeholders) + ")"
        for row_placeholders in all_rows_placeholders
    )

    sql = f"INSERT INTO {hashes_table_name}" \
          f"({foreign_key_name}, hash_name, hash_value)" \
          f" VALUES {all_rows_placeholders_sql}"

    print("HASHES sql (", hashes_table_name, "): ", sql, sep="")
    print("Hashes:", bindings)
    return [(sql, bindings)]


def generate_insert_for_granular_markings(granular_markings, markings_table_name, **foreign_key):
    foreign_key_column, foreign_key_value = next(iter(foreign_key.items()))

    bindings = {
        foreign_key_column: foreign_key_value
    }

    all_rows_placeholders = []
    for idx, granular_marking in enumerate(granular_markings):
        lang_binding_name = f"lang{idx}"
        marking_ref_binding_name = f"marking_ref{idx}"
        selectors_binding_name = f"selectors{idx}"

        all_rows_placeholders.append([
            f"%({foreign_key_column})s",
            f"%({lang_binding_name})s",
            f"%({marking_ref_binding_name})s",
            f"%({selectors_binding_name})s"
        ])

        bindings[lang_binding_name] = granular_marking.get("lang")
        bindings[marking_ref_binding_name] = granular_marking.get("marking_ref")
        bindings[selectors_binding_name] = granular_marking.get("selectors")

    all_rows_placeholders_sql = ", ".join(
        "(" + ", ".join(row_placeholders) + ")"
        for row_placeholders in all_rows_placeholders
    )

    sql = f'INSERT INTO {markings_table_name}' \
          f" ({foreign_key_column}, lang, marking_ref, selectors)" \
          f" VALUES {all_rows_placeholders_sql}"

    print("GRANULAR MARKINGS sql (", markings_table_name, "): ", sql, sep="")
    print("granular:", bindings)
    return [(sql, bindings)]


def generate_insert_for_extensions(extensions, foreign_key_value, type_name, core_properties):
    sql_bindings_tuples = list()
    for name, ex in extensions.items():
        sql_bindings_tuples.extend(generate_insert_for_subtype_extension(name,
                                                                         ex,
                                                                         foreign_key_value,
                                                                         type_name,
                                                                         core_properties))
    return sql_bindings_tuples


def generate_insert_for_subtype_extension(name, ex, foreign_key_value, type_name, core_properties):
    sql_bindings_tuples = list()
    properties = ex._properties

    bindings, values = generate_single_values(ex, properties, core_properties)
    bindings["id"] = foreign_key_value
    sql = f"INSERT INTO {canonicalize_table_name(type_name, name)}" \
          f" ({','.join(bindings.keys())})" \
          f" VALUES ({','.join(values)}, %(id)s)"

    print("sql:", sql)
    print("ext:", bindings)
    sql_bindings_tuples.append((sql, bindings))
    if "external_references" in ex:
        sql_bindings_tuples.extend(generate_insert_for_external_references(ex["external_references"], ex["id"]))

    for name, prop in properties.items():
        if table_property(prop, name, core_properties):
            if name in ex:
                if embedded_object_list_property(prop, name, core_properties):
                    sql_bindings_tuples.extend(generate_insert_for_embedded_objects(ex["type"], ex[name], ex["id"]))
                elif isinstance(prop, DictionaryProperty) and name not in core_properties:
                    sql_bindings_tuples.extend(generate_insert_for_dictionary_object(type_name, ex[name], name, foreign_key_value))
                else:
                    sql_bindings_tuples.extend(generate_insert_for_array_in_table(ex["type"], name, ex[name], properties[name],
                                                       ex["id"]))
    return sql_bindings_tuples


def generate_insert_for_core(stix_object, core_properties):
    kind_of_stix_object = "sdo" if "created" in core_properties else "sco"
    sql_bindings_tuples = list()
    core_bindings = {}

    for prop_name, value in stix_object.items():

        if prop_name in core_properties:
            # stored in separate tables, skip here
            if prop_name not in {
                "object_marking_refs", "granular_markings", "external_references"
            }:
                core_bindings[prop_name] = value

    core_col_names = ", ".join(core_bindings)
    core_placeholders = ", ".join(
        f"%({name})s" for name in core_bindings
    )
    sql = f"INSERT INTO common.core_{kind_of_stix_object} ({core_col_names}) VALUES ({core_placeholders})"
    print("CORE sql:", sql)
    print(core_bindings)
    sql_bindings_tuples.append((sql, core_bindings))

    if "object_marking_refs" in stix_object:
        sql_bindings_tuples.extend(generate_insert_for_array_in_table(
            "core",
            "object_marking_refs",
            stix_object.object_marking_refs,
            stix_object._properties["object_marking_refs"],
            stix_object.id
        ))

    # Granular markings
    if "granular_markings" in stix_object:
        sql_bindings_tuples.extend(generate_insert_for_granular_markings(
            stix_object.granular_markings, "common.granular_marking_stix_object",
            core_id=stix_object.id
        ))

    if "extensions" in stix_object:
        sql_bindings_tuples.extend(generate_insert_for_extensions(stix_object.extensions,
                                                                  stix_object.id,
                                                                  stix_object.type,
                                                                  core_properties))
    return sql_bindings_tuples

