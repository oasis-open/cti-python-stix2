from sqlalchemy import insert

from stix2.datastore.relational_db.add_method import add_method
from stix2.datastore.relational_db.utils import (
    SCO_COMMON_PROPERTIES, SDO_COMMON_PROPERTIES, canonicalize_table_name,
)
from stix2.properties import (
    BinaryProperty, BooleanProperty, DictionaryProperty,
    EmbeddedObjectProperty, EnumProperty, ExtensionsProperty, FloatProperty,
    HashesProperty, HexProperty, IDProperty, IntegerProperty, ListProperty,
    Property, ReferenceProperty, StringProperty, TimestampProperty,
)
from stix2.utils import STIXdatetime
from stix2.v21.common import KillChainPhase

# =========================================================================
# generate_insert_information methods

# positional arguments
#
#   name:               property name
#   stix_object:        STIX object data to be inserted in the table

# optional arguments
#
#   data_sink:          STIX data sink object
#   table_name:         name of the related table
#   schema_name:        name of the schema for the related table, if it exists
#   parent_table_name:  the name of the parent table, if called for a child table
#   level:              what "level" of child table is involved
#   foreign_key_value:


@add_method(Property)
def generate_insert_information(self, name, stix_object, **kwargs):  # noqa: F811
    pass


@add_method(BinaryProperty)
def generate_insert_information(self, name, stix_object, **kwargs):  # noqa: F811
    return {name: stix_object[name]}


@add_method(BooleanProperty)
def generate_insert_information(self, name, stix_object, **kwargs):  # noqa: F811
    return {name: stix_object[name]}


def instance_in_valid_types(cls, valid_types):
    for v in valid_types:
        if isinstance(v, cls):
            return True
    return False


def is_valid_type(cls, valid_types):
    return cls in valid_types or instance_in_valid_types(cls, valid_types)


def generate_insert_for_dictionary_list(table, next_id, value):
    insert_stmts = list()
    for v in value:
        bindings = dict()
        bindings["id"] = next_id
        bindings["value"] = v
        insert_stmts.append(insert(table).values(bindings))
    return insert_stmts


@add_method(DictionaryProperty)
def generate_insert_information(self, dictionary_name, stix_object, **kwargs):  # noqa: F811
    bindings = dict()
    data_sink = kwargs.get("data_sink")
    table_name = kwargs.get("table_name")
    schema_name = kwargs.get("schema_name")
    foreign_key_value = kwargs.get("foreign_key_value")
    insert_statements = list()

    table = data_sink.tables_dictionary[
        canonicalize_table_name(
            table_name + "_" + dictionary_name,
            schema_name,
        )
    ]

    # binary, boolean, float, hex,
    # integer, string, timestamp
    valid_types = stix_object._properties[dictionary_name].valid_types
    child_table_inserts = list()
    for name, value in stix_object[dictionary_name].items():
        bindings = dict()
        if "id" in stix_object:
            bindings["id"] = stix_object["id"]
        elif foreign_key_value:
            bindings["id"] = foreign_key_value
        if not valid_types or len(self.valid_types) == 1:
            if is_valid_type(ListProperty, valid_types):
                value_binding = "values"
                if not data_sink.db_backend.array_allowed():
                    next_id = data_sink.db_backend.next_id(data_sink)
                    table_child = data_sink.tables_dictionary[
                        canonicalize_table_name(table_name + "_" + dictionary_name + "_" + "values", schema_name)
                    ]
                    child_table_inserts = generate_insert_for_dictionary_list(table_child, next_id, value)
                    value = next_id
            else:
                value_binding = "value"
        elif isinstance(value, int) and is_valid_type(IntegerProperty, valid_types):
            value_binding = "integer_value"
        elif isinstance(value, str) and is_valid_type(StringProperty, valid_types):
            value_binding = "string_value"
        elif isinstance(value, bool) and is_valid_type(BooleanProperty, valid_types):
            value_binding = "boolean_value"
        elif isinstance(value, float) and is_valid_type(FloatProperty, valid_types):
            value_binding = "float_value"
        elif isinstance(value, STIXdatetime) and is_valid_type(TimestampProperty, valid_types):
            value_binding = "timestamp_value"
        else:
            value_binding = "string_value"

        bindings["name"] = name
        bindings[value_binding] = value

        insert_statements.append(insert(table).values(bindings))

    insert_statements.extend(child_table_inserts)
    return insert_statements


@add_method(EmbeddedObjectProperty)
def generate_insert_information(self, name, stix_object, is_list=False, foreign_key_value=None, is_extension=False, **kwargs):  # noqa: F811
    data_sink = kwargs.get("data_sink")
    schema_name = kwargs.get("schema_name")
    level = kwargs.get("level")
    return generate_insert_for_sub_object(
        data_sink, stix_object[name], self.type.__name__, schema_name,
        level=level+1 if is_list else level,
        is_embedded_object=True,
        is_extension=is_extension,
        parent_table_name=kwargs.get("parent_table_name"),
        foreign_key_value=foreign_key_value,
    )


@add_method(EnumProperty)
def generate_insert_information(self, name, stix_object, **kwargs):  # noqa: F811
    return {name: stix_object[name]}


@add_method(ExtensionsProperty)
def generate_insert_information(self, name, stix_object, data_sink=None, table_name=None, schema_name=None, parent_table_name=None, **kwargs):  # noqa: F811
    input_statements = list()
    for ex_name, ex in stix_object["extensions"].items():
        # ignore new extensions - they have no properties
        if ex.extension_type is None or not ex.extension_type.startswith("new"):
            if ex_name.startswith("extension-definition"):
                ex_name = ex_name[0:30]
                ex_name = ex_name.replace("extension-definition-", "ext_def")
            bindings = {
                "id": stix_object["id"],
                "ext_table_name": canonicalize_table_name(ex_name, schema_name),
            }
            ex_table = data_sink.tables_dictionary[canonicalize_table_name(table_name + "_" + "extensions", schema_name)]
            input_statements.append(insert(ex_table).values(bindings))
            input_statements.extend(
                generate_insert_for_sub_object(
                    data_sink, ex, ex_name, schema_name, stix_object["id"],
                    parent_table_name=parent_table_name,
                    is_extension=True,
                ),
            )
    return input_statements


@add_method(FloatProperty)
def generate_insert_information(self, name, stix_object, **kwargs):  # noqa: F811
    return {name: stix_object[name]}


@add_method(HexProperty)
def generate_insert_information(self, name, stix_object, data_sink, **kwargs):  # noqa: F811
    return {name: data_sink.db_backend.process_value_for_insert(self, stix_object[name])}


def generate_insert_for_hashes(
    data_sink, name, stix_object, table_name, schema_name, foreign_key_value=None,
    is_embedded_object=False, **kwargs,
):
    bindings = {"id": foreign_key_value}
    table_name = canonicalize_table_name(table_name + "_" + name, schema_name)
    table = data_sink.tables_dictionary[table_name]
    insert_statements = list()
    for hash_name, hash_value in stix_object["hashes"].items():

        bindings["hash_name"] = hash_name
        bindings["hash_value"] = hash_value
        insert_statements.append(insert(table).values(bindings))
    return insert_statements


@add_method(HashesProperty)
def generate_insert_information(   # noqa: F811
    self, name, stix_object, data_sink=None, table_name=None, schema_name=None,
    is_embedded_object=False, foreign_key_value=None, is_list=False, **kwargs,
):
    return generate_insert_for_hashes(
        data_sink, name, stix_object, table_name, schema_name,
        is_embedded_object=is_embedded_object, is_list=is_list, foreign_key_value=foreign_key_value,
    )


@add_method(IDProperty)
def generate_insert_information(self, name, stix_object, **kwargs):  # noqa: F811
    return {name: stix_object[name]}


@add_method(IntegerProperty)
def generate_insert_information(self, name, stix_object, **kwargs):  # noqa: F811
    return {name: stix_object[name]}


@add_method(ListProperty)
def generate_insert_information(   # noqa: F811
    self, name, stix_object, data_sink=None, level=0, is_extension=False,
    foreign_key_value=None, schema_name=None, **kwargs,
):
    db_backend = data_sink.db_backend
    table_name = kwargs.get("table_name")
    if isinstance(self.contained, ReferenceProperty):
        insert_statements = list()

        table = data_sink.tables_dictionary[canonicalize_table_name(table_name + "_" + name, schema_name)]
        for idx, item in enumerate(stix_object[name]):
            bindings = {
                "id": stix_object["id"] if id in stix_object else foreign_key_value,
                "ref_id": item,
            }
            insert_statements.append(insert(table).values(bindings))
        return insert_statements
    elif self.contained == KillChainPhase:
        insert_statements = list()
        table = data_sink.tables_dictionary[canonicalize_table_name(table_name + "_" + name, schema_name)]

        for idx, item in enumerate(stix_object[name]):
            bindings = {
                "id": stix_object["id"] if id in stix_object else foreign_key_value,
                "kill_chain_name": item["kill_chain_name"],
                "phase_name": item["phase_name"],
            }
            insert_statements.append(insert(table).values(bindings))
        return insert_statements
    elif isinstance(self.contained, EnumProperty):
        insert_statements = list()
        table = data_sink.tables_dictionary[canonicalize_table_name(table_name + "_" + name, schema_name)]

        for idx, item in enumerate(stix_object[name]):
            bindings = {
                "id": stix_object["id"] if id in stix_object else foreign_key_value,
                name: item,
            }
            insert_statements.append(insert(table).values(bindings))
        return insert_statements
    elif isinstance(self.contained, EmbeddedObjectProperty):
        insert_statements = list()
        for value in stix_object[name]:
            next_id = db_backend.next_id(data_sink)
            table = data_sink.tables_dictionary[canonicalize_table_name(table_name + "_" + name, schema_name)]
            bindings = {
                "id": foreign_key_value,
                "ref_id": next_id,
            }
            insert_statements.append(insert(table).values(bindings))
            insert_statements.extend(
                generate_insert_for_sub_object(
                    data_sink,
                    value,
                    table_name + "_" + name + "_" + self.contained.type.__name__,
                    schema_name,
                    next_id,
                    level,
                    True,
                    is_extension=is_extension,
                ),
            )
        return insert_statements
    else:
        if db_backend.array_allowed():
            if isinstance(self.contained, HexProperty):
                return {name: [data_sink.db_backend.process_value_for_insert(self.contained, x) for x in stix_object[name]]}
            else:
                return {name: stix_object[name]}

        else:
            insert_statements = list()
            table = data_sink.tables_dictionary[
                canonicalize_table_name(
                    table_name + "_" + name,
                    schema_name,
                )
            ]
            for elem in stix_object[name]:
                bindings = {
                    "id": stix_object["id"],
                    name: db_backend.process_value_for_insert(self.contained, elem),
                }
                insert_statements.append(insert(table).values(bindings))
            return insert_statements


@add_method(ReferenceProperty)
def generate_insert_information(self, name, stix_object, **kwargs):  # noqa: F811
    return {name: stix_object[name]}


@add_method(StringProperty)
def generate_insert_information(self, name, stix_object, **kwargs):  # noqa: F811
    return {name: stix_object[name]}


@add_method(TimestampProperty)
def generate_insert_information(self, name, stix_object, **kwargs):  # noqa: F811
    db_backend = kwargs["data_sink"].db_backend
    return {name: db_backend.process_value_for_insert(self, stix_object[name])}


# =========================================================================


def derive_column_name(prop):
    contained_property = prop.contained
    if isinstance(contained_property, ReferenceProperty):
        return "ref_id"
    elif isinstance(contained_property, StringProperty):
        return "value"


def generate_insert_for_array_in_table(table, values, foreign_key_value, column_name="ref_id"):
    insert_statements = list()
    for idx, item in enumerate(values):
        bindings = {
            "id": foreign_key_value,
            column_name: item,
        }
        insert_statements.append(insert(table).values(bindings))
    return insert_statements


def generate_insert_for_external_references(data_sink, stix_object):
    insert_statements = list()
    next_id = None
    schema_name = data_sink.db_backend.schema_for_core()
    object_table = data_sink.tables_dictionary[canonicalize_table_name("external_references", schema_name)]
    for er in stix_object["external_references"]:
        bindings = {"id": stix_object["id"]}
        for prop in ["source_name", "description", "url", "external_id"]:
            if prop in er:
                bindings[prop] = er[prop]
        if "hashes" in er:
            next_id = data_sink.db_backend.next_id(data_sink)
            bindings["hash_ref_id"] = next_id
        # else:
        #     # hash_ref_id is non-NULL, so -1 means there are no hashes
        #     bindings["hash_ref_id"] = -1
        er_insert_statement = insert(object_table).values(bindings)
        insert_statements.append(er_insert_statement)

        if "hashes" in er:
            insert_statements.extend(
                generate_insert_for_hashes(
                    data_sink,
                    "hashes",
                    er,
                    "external_references",
                    schema_name,
                    foreign_key_value=next_id,
                ),
            )

    return insert_statements


def generate_insert_for_granular_markings(data_sink, granular_markings_table, stix_object):
    db_backend = data_sink.db_backend
    insert_statements = list()
    granular_markings = stix_object["granular_markings"]
    for idx, granular_marking in enumerate(granular_markings):
        bindings = {"id": stix_object["id"]}
        lang_property_value = granular_marking.get("lang")
        if lang_property_value:
            bindings["lang"] = lang_property_value
        marking_ref_value = granular_marking.get("marking_ref")
        if marking_ref_value:
            bindings["marking_ref"] = marking_ref_value
        if db_backend.array_allowed():
            bindings["selectors"] = granular_marking.get("selectors")
            insert_statements.append(insert(granular_markings_table).values(bindings))
        else:
            next_id = db_backend.next_id(data_sink)
            bindings["selectors"] = next_id
            insert_statements.append(insert(granular_markings_table).values(bindings))
            table = data_sink.tables_dictionary[
                canonicalize_table_name(
                    granular_markings_table.name + "_selector",
                    db_backend.schema_for_core(),
                )
            ]
            for sel in granular_marking.get("selectors"):
                selector_bindings = {"id": next_id, "selector": sel}
                insert_statements.append(insert(table).values(selector_bindings))

    return insert_statements


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


def generate_insert_for_core(data_sink, stix_object, core_properties, stix_type_name, schema_name):
    db_backend = data_sink.db_backend
    if stix_type_name in ["sdo", "sro", "common"]:
        core_table = data_sink.tables_dictionary[canonicalize_table_name("core_sdo", db_backend.schema_for_core())]
    else:
        core_table = data_sink.tables_dictionary[canonicalize_table_name("core_sco", db_backend.schema_for_core())]
    insert_statements = list()
    core_bindings = {}

    child_table_properties = ["object_marking_refs", "granular_markings", "external_references", "type"]
    if "labels" in core_properties and not db_backend.array_allowed():
        child_table_properties.append("labels")

    for prop_name, value in stix_object.items():
        if prop_name in core_properties:
            # stored in separate tables below, skip here
            if prop_name not in child_table_properties:
                core_bindings[prop_name] = db_backend.process_value_for_insert(stix_object._properties[prop_name], value)

    core_insert_statement = insert(core_table).values(core_bindings)
    insert_statements.append(core_insert_statement)

    if "labels" in stix_object and "labels" in child_table_properties:
        label_table_name = canonicalize_table_name(core_table.name + "_labels", data_sink.db_backend.schema_for_core())
        labels_table = data_sink.tables_dictionary[label_table_name]
        insert_statements.extend(
            generate_insert_for_array_in_table(
                labels_table,
                stix_object["labels"],
                stix_object["id"],
                column_name="label",
            ),
        )

    if "object_marking_refs" in stix_object:
        object_marking_table_name = canonicalize_table_name(
            "object_marking_refs",
            data_sink.db_backend.schema_for_core(),
        )
        if stix_type_name != "sco":
            object_markings_ref_table = data_sink.tables_dictionary[object_marking_table_name + "_sdo"]
        else:
            object_markings_ref_table = data_sink.tables_dictionary[object_marking_table_name + "_sco"]
        insert_statements.extend(
            generate_insert_for_array_in_table(
                object_markings_ref_table,
                stix_object["object_marking_refs"],
                stix_object["id"],
            ),
        )

    # Granular markings
    if "granular_markings" in stix_object:
        granular_marking_table_name = canonicalize_table_name(
            "granular_marking",
            data_sink.db_backend.schema_for_core(),
        )
        if stix_type_name != "sco":
            granular_marking_table = data_sink.tables_dictionary[granular_marking_table_name + "_sdo"]
        else:
            granular_marking_table = data_sink.tables_dictionary[granular_marking_table_name + "_sco"]
        granular_input_statements = generate_insert_for_granular_markings(
            data_sink,
            granular_marking_table,
            stix_object,
        )
        insert_statements.extend(granular_input_statements)

    return insert_statements


def generate_insert_for_sub_object(
    data_sink, stix_object, type_name, schema_name, foreign_key_value=None,
    is_embedded_object=False, is_list=False, parent_table_name=None, level=0,
    is_extension=False,
):
    insert_statements = list()
    bindings = dict()
    if "id" in stix_object:
        bindings["id"] = stix_object["id"]
    elif foreign_key_value:
        bindings["id"] = foreign_key_value
    if parent_table_name and (not is_extension or level > 0):
        type_name = parent_table_name + "_" + type_name
    if type_name.startswith("extension-definition"):
        type_name = type_name[0:30]
        type_name = type_name.replace("extension-definition-", "ext_def")
    sub_insert_statements = list()
    for name, prop in stix_object._properties.items():
        if name in stix_object:
            result = prop.generate_insert_information(
                name,
                stix_object,
                data_sink=data_sink,
                table_name=type_name if isinstance(prop, (DictionaryProperty, ListProperty)) else parent_table_name,
                schema_name=schema_name,
                foreign_key_value=foreign_key_value,
                is_embedded_object=is_embedded_object,
                is_list=is_list,
                level=level+1,
                is_extension=is_extension,
                parent_table_name=type_name,
            )
            if isinstance(result, dict):
                bindings.update(result)
            elif isinstance(result, list):
                sub_insert_statements.extend(result)
            else:
                raise ValueError("wrong type" + result)
    if foreign_key_value:
        bindings["id"] = foreign_key_value
    object_table = data_sink.tables_dictionary[canonicalize_table_name(type_name, schema_name)]
    insert_statements.append(insert(object_table).values(bindings))
    insert_statements.extend(sub_insert_statements)
    return insert_statements


def generate_insert_for_object(data_sink, stix_object, stix_type_name, schema_name, level=0):
    insert_statements = list()
    bindings = dict()
    if stix_type_name == "sco":
        core_properties = SCO_COMMON_PROPERTIES
    elif stix_type_name in ["sdo", "sro", "common"]:
        core_properties = SDO_COMMON_PROPERTIES
    else:
        core_properties = list()
    type_name = stix_object["type"]
    if core_properties:
        insert_statements.extend(generate_insert_for_core(data_sink, stix_object, core_properties, stix_type_name, schema_name))
    if "id" in stix_object:
        foreign_key_value = stix_object["id"]
    else:
        foreign_key_value = None
    sub_insert_statements = list()
    for name, prop in stix_object._properties.items():
        if (name == 'id' or name not in core_properties) and name != "type" and name in stix_object:
            result = prop.generate_insert_information(
                name, stix_object,
                data_sink=data_sink,
                table_name=type_name,
                schema_name=schema_name,
                parent_table_name=type_name,
                level=level,
                foreign_key_value=foreign_key_value,
            )
            if isinstance(result, dict):
                bindings.update(result)
            elif isinstance(result, list):
                sub_insert_statements.extend(result)
            else:
                raise ValueError("wrong type" + result)

    object_table = data_sink.tables_dictionary[canonicalize_table_name(type_name, schema_name)]
    insert_statements.append(insert(object_table).values(bindings))
    insert_statements.extend(sub_insert_statements)

    if "external_references" in stix_object:
        insert_statements.extend(generate_insert_for_external_references(data_sink, stix_object))

    return insert_statements
