from sqlalchemy import (  # create_engine,; insert,
    ARRAY, CheckConstraint, Column, ForeignKey, Integer, Table, Text,
    UniqueConstraint,
)

from stix2.datastore.relational_db.add_method import add_method
from stix2.datastore.relational_db.utils import (
    canonicalize_table_name, determine_column_name, determine_core_properties,
    determine_sql_type_from_stix, flat_classes, get_stix_object_classes,
    shorten_extension_definition_id,
)
from stix2.properties import (
    BinaryProperty, BooleanProperty, DictionaryProperty,
    EmbeddedObjectProperty, EnumProperty, ExtensionsProperty, FloatProperty,
    HashesProperty, HexProperty, IDProperty, IntegerProperty, ListProperty,
    ObjectReferenceProperty, Property, ReferenceProperty, StringProperty,
    TimestampProperty, TypeProperty,
)
from stix2.v21.base import _Extension, _Observable
from stix2.v21.common import KillChainPhase


def create_array_column(property_name, contained_sql_type, optional):
    return Column(
        property_name,
        ARRAY(contained_sql_type),
        CheckConstraint(f"{property_name} IS NULL or array_length({property_name}, 1) IS NOT NULL"),
        nullable=optional,
    )


def create_array_child_table(
    metadata, db_backend, parent_table_name, schema_name, table_name_suffix, property_name,
    contained_sql_type, foreign_key_property="id",
):
    columns = [
        Column(
            foreign_key_property,
            db_backend.determine_sql_type_for_key_as_id(),
            ForeignKey(
                 canonicalize_table_name(parent_table_name, schema_name) + "." + foreign_key_property,
                 ondelete="CASCADE",
            ),
            nullable=False,
        ),
        Column(
            property_name,
            contained_sql_type,
            nullable=False,
        ),
    ]
    return Table(canonicalize_table_name(parent_table_name + table_name_suffix), metadata, *columns, schema=schema_name)


def derive_column_name(prop):
    contained_property = prop.contained
    if isinstance(contained_property, ReferenceProperty):
        return "ref_id"
    elif isinstance(contained_property, StringProperty):
        return "value"


def create_object_markings_refs_table(metadata, db_backend, sco_or_sdo):
    schema_name = db_backend.schema_for_core()
    return create_ref_table(
        metadata,
        db_backend,
        {"marking-definition"},
        "object_marking_refs_" + sco_or_sdo,
        canonicalize_table_name("core_" + sco_or_sdo, schema_name) + ".id",
        schema_name,
        0,
    )


def create_ref_table(metadata, db_backend, specifics, table_name, foreign_key_name, schema_name, auth_type=0):
    columns = list()
    columns.append(
        Column(
            "id",
            db_backend.determine_sql_type_for_key_as_id(),
            ForeignKey(
                foreign_key_name,
                ondelete="CASCADE",
            ),
            nullable=False,
        ),
    )
    columns.append(ref_column("ref_id", specifics, db_backend, auth_type))
    return Table(table_name, metadata, *columns, schema=schema_name)


def create_hashes_table(name, metadata, db_backend, schema_name, table_name, key_type=Text, level=1):
    columns = list()
    # special case, perhaps because its a single embedded object with hashes, and not a list of embedded object
    # making the parent table's primary key does seem to work

    columns.append(
        Column(
            "id",
            key_type,
            # ForeignKey(
            #     canonicalize_table_name(table_name, schema_name) + (".hash_ref_id" if table_name == "external_references" else ".id"),
            #     ondelete="CASCADE",
            # ),

            nullable=False,
        ),
    )
    columns.append(
        Column(
            "hash_name",
            db_backend.determine_sql_type_for_string_property(),
            nullable=False,
        ),
    )
    columns.append(
        Column(
            "hash_value",
            db_backend.determine_sql_type_for_string_property(),
            nullable=False,
        ),
    )
    return Table(
        canonicalize_table_name(table_name + "_" + name),
        metadata,
        *columns,
        UniqueConstraint("id", "hash_name"),
        schema=schema_name,
    )


def create_kill_chain_phases_table(name, metadata, db_backend, schema_name, table_name):
    columns = list()
    columns.append(
        Column(
            "id",
            db_backend.determine_sql_type_for_key_as_id(),
            ForeignKey(
                canonicalize_table_name(table_name, schema_name) + ".id",
                ondelete="CASCADE",
            ),
            nullable=False,
        ),
    )
    columns.append(
        Column(
            "kill_chain_name",
            db_backend.determine_sql_type_for_string_property(),
            nullable=False,
        ),
    )
    columns.append(
        Column(
            "phase_name",
            db_backend.determine_sql_type_for_string_property(),
            nullable=False,
        ),
    )
    return Table(canonicalize_table_name(table_name + "_" + name), metadata, *columns, schema=schema_name)


def create_granular_markings_table(metadata, db_backend, sco_or_sdo):
    schema_name = db_backend.schema_for_core()
    tables = list()
    reg_ex = "'^marking-definition--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'"  # noqa: E131
    columns = [
        Column(
            "id",
            db_backend.determine_sql_type_for_key_as_id(),
            ForeignKey(canonicalize_table_name("core_" + sco_or_sdo, schema_name) + ".id", ondelete="CASCADE"),
            nullable=False,
        ),
        Column("lang", db_backend.determine_sql_type_for_string_property()),
        Column(
            "marking_ref",
            db_backend.determine_sql_type_for_reference_property(),
            db_backend.create_regex_constraint_expression("marking_ref", reg_ex),
        ),
    ]
    if db_backend.array_allowed():
        columns.append(create_array_column("selectors", db_backend.determine_sql_type_for_string_property(), False))

    else:
        columns.append(
            Column(
                    "selectors",
                    db_backend.determine_sql_type_for_key_as_int(),
                    unique=True,
            ),
        )

        child_columns = [
            Column(
                "id",
                db_backend.determine_sql_type_for_key_as_int(),
                ForeignKey(
                    canonicalize_table_name("granular_marking_" + sco_or_sdo, schema_name) + ".selectors",
                    ondelete="CASCADE",
                ),
                nullable=False,
            ),
            Column(
                "selector",
                db_backend.determine_sql_type_for_string_property(),
                nullable=False,
            ),
        ]
        tables.append(
            Table(
                canonicalize_table_name("granular_marking_" + sco_or_sdo + "_" + "selector"),
                metadata, *child_columns, schema=schema_name,
            ),
        )
    tables.append(
        Table(
            "granular_marking_" + sco_or_sdo,
            metadata,
            *columns,
            CheckConstraint(
                """(lang IS NULL AND marking_ref IS NOT NULL)
                      OR
                      (lang IS NOT NULL AND marking_ref IS NULL)""",
            ),
            schema=schema_name,
        ),
    )
    return tables


def create_external_references_tables(metadata, db_backend):
    reg_ex = "'^[a-z][a-z0-9-]+[a-z0-9]--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'"  # noqa: E131
    schema_name = db_backend.schema_for_core()
    columns = [
        Column(
            "id",
            db_backend.determine_sql_type_for_key_as_id(),
            ForeignKey(canonicalize_table_name("core_sdo", schema_name) + ".id", ondelete="CASCADE"),
            db_backend.create_regex_constraint_expression("id", reg_ex),
        ),
        Column("source_name", db_backend.determine_sql_type_for_string_property()),
        Column("description", db_backend.determine_sql_type_for_string_property()),
        Column("url", db_backend.determine_sql_type_for_string_property()),
        Column("external_id", db_backend.determine_sql_type_for_string_property()),
        # all such keys are generated using the global sequence.
        Column("hash_ref_id", db_backend.determine_sql_type_for_key_as_int(), autoincrement=False),
    ]
    return [
        Table("external_references", metadata, *columns, schema=schema_name),
        create_hashes_table("hashes", metadata, db_backend, schema_name, "external_references", Integer),
    ]


def create_core_table(metadata, db_backend, stix_type_name):
    tables = list()
    table_name = "core_" + stix_type_name
    reg_ex = "'^[a-z][a-z0-9-]+[a-z0-9]--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'"  # noqa: E131
    columns = [
        Column(
            "id",
            db_backend.determine_sql_type_for_key_as_id(),
            db_backend.create_regex_constraint_expression("id", reg_ex),
            primary_key=True,
        ),
        Column("spec_version", db_backend.determine_sql_type_for_string_property(), default="2.1"),
    ]
    if stix_type_name == "sdo":
        reg_ex = "'^identity--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'"  # noqa: E131
        sdo_columns = [
            Column(
                "created_by_ref",
                db_backend.determine_sql_type_for_reference_property(),
                db_backend.create_regex_constraint_expression("created_by_ref", reg_ex),
            ),
            Column("created", db_backend.determine_sql_type_for_timestamp_property()),
            Column("modified", db_backend.determine_sql_type_for_timestamp_property()),
            Column("revoked", db_backend.determine_sql_type_for_boolean_property()),
            Column(
                "confidence",
                db_backend.determine_sql_type_for_integer_property(),
                db_backend.create_min_max_constraint_expression(IntegerProperty(min=0, max=100), "confidence"),
            ),
            Column("lang", db_backend.determine_sql_type_for_string_property()),
        ]
        columns.extend(sdo_columns)
        if db_backend.array_allowed():
            columns.append(create_array_column("labels", db_backend.determine_sql_type_for_string_property(), True))
        else:
            tables.append(
                create_array_child_table(
                    metadata,
                    db_backend,
                    table_name,
                    db_backend.schema_for_core(),
                    "_labels",
                    "label",
                    db_backend.determine_sql_type_for_string_property(),
                ),
            )
    else:
        columns.append(Column("defanged", db_backend.determine_sql_type_for_boolean_property(), default=False))

    tables.append(
        Table(
            table_name,
            metadata,
            *columns,
            schema=db_backend.schema_for_core(),
        ),
    )
    return tables

# =========================================================================
# sql type methods

# STIX classes defer to the DB backend


@add_method(Property)
def determine_sql_type(self, db_backend):  # noqa: F811
    pass


@add_method(KillChainPhase)
def determine_sql_type(self, db_backend):  # noqa: F811
    return db_backend.determine_sql_type_for_kill_chain_phase()


@add_method(BinaryProperty)
def determine_sql_type(self, db_backend):  # noqa: F811
    return db_backend.determine_sql_type_for_binary_property()


@add_method(BooleanProperty)
def determine_sql_type(self, db_backend):  # noqa: F811
    return db_backend.determine_sql_type_for_boolean_property()


@add_method(FloatProperty)
def determine_sql_type(self, db_backend):  # noqa: F811
    return db_backend.determine_sql_type_for_float_property()


@add_method(HexProperty)
def determine_sql_type(self, db_backend):  # noqa: F811
    return db_backend.determine_sql_type_for_hex_property()


@add_method(IntegerProperty)
def determine_sql_type(self, db_backend):  # noqa: F811
    return db_backend.determine_sql_type_for_integer_property()


@add_method(ReferenceProperty)
def determine_sql_type(self, db_backend):  # noqa: F811
    return db_backend.determine_sql_type_for_reference_property()


@add_method(StringProperty)
def determine_sql_type(self, db_backend):  # noqa: F811
    return db_backend.determine_sql_type_for_string_property()


@add_method(TimestampProperty)
def determine_sql_type(self, db_backend):  # noqa: F811
    return db_backend.determine_sql_type_for_timestamp_property()

# =========================================================================
# generate_table_information methods

# positional arguments
#
#
#   name                property name
#   db_backend          Class instance related to the database backend

# optional arguments
#
#   metadata:           SQL Alchemy metadata
#   schema_name:        name of the schema for the related table, if it exists
#   table_name:         name of the related table
#   is_extension:       is this related to a table for an extension
#   is_embedded_object: is this related to a table for an extension
#   is_list:            is this property a list?
#   level:              what "level" of child table is involved
#   parent_table_name:  the name of the parent table, if called for a child table
#   core_table:         name of the related core table


@add_method(KillChainPhase)
def generate_table_information(  # noqa: F811
        self, name, db_backend, metadata, schema_name, table_name, is_extension=False, is_list=False,
        **kwargs,
):
    level = kwargs.get("level")
    return generate_object_table(
        self.type, metadata, schema_name, table_name, is_extension, True, is_list,
        parent_table_name=table_name, level=level + 1 if is_list else level,
    )


@add_method(Property)
def generate_table_information(self, name, db_backend, **kwargs):   # noqa: F811
    pass


@add_method(BinaryProperty)
def generate_table_information(self, name, db_backend, **kwargs):  # noqa: F811
    return Column(
        name,
        self.determine_sql_type(db_backend),
        # this regular expression might accept or reject some legal base64 strings
        db_backend.create_regex_constraint_expression(name, "'^[-A-Za-z0-9+/]*={0,3}$'"),
        nullable=not self.required,
    )


@add_method(BooleanProperty)
def generate_table_information(self, name, db_backend, **kwargs):  # noqa: F811
    return Column(
        name,
        self.determine_sql_type(db_backend),
        nullable=not self.required,
        default=self._fixed_value if hasattr(self, "_fixed_value") else None,
    )


@add_method(DictionaryProperty)
def generate_table_information(self, name, db_backend, metadata, schema_name, table_name, is_extension=False, **kwargs):  # noqa: F811
    columns = list()
    tables = list()
    columns.append(
        Column(
            "id",
            db_backend.determine_sql_type_for_key_as_id(),
            ForeignKey(canonicalize_table_name(table_name, schema_name) + ".id", ondelete="CASCADE"),
        ),
    )
    columns.append(
        Column(
            "name",
            db_backend.determine_sql_type_for_string_property(),
            nullable=False,
        ),
    )
    if self.valid_types:
        if len(self.valid_types) == 1:
            if not isinstance(self.valid_types[0], ListProperty):
                columns.append(
                    Column(
                        "value",
                        # its a class
                        determine_sql_type_from_stix(self.valid_types[0], db_backend),
                        nullable=False,

                    ),
                )
            else:
                contained_class = self.valid_types[0].contained
                if db_backend.array_allowed():
                    columns.append(
                        create_array_column(
                            "values",
                            contained_class.determine_sql_type(db_backend),
                            False,
                        ),
                    )
                else:
                    columns.append(
                        Column(
                            "values",
                            db_backend.determine_sql_type_for_key_as_int(),
                            unique=True,
                        ),
                    )
                    child_columns = [
                        Column(
                            "id",
                            db_backend.determine_sql_type_for_key_as_int(),
                            ForeignKey(
                                canonicalize_table_name(table_name + "_" + name, schema_name) + ".values",
                                ondelete="CASCADE",
                            ),
                            nullable=False,
                        ),
                        Column(
                            "value",
                            contained_class.determine_sql_type(db_backend),
                            nullable=False,
                        ),
                    ]
                    tables.append(
                        Table(
                            canonicalize_table_name(table_name + "_" + name + "_" + "values"),
                            metadata, *child_columns, schema=schema_name,
                        ),
                    )
        else:
            for column_type in self.valid_types:
                sql_type = determine_sql_type_from_stix(column_type, db_backend)
                columns.append(
                    Column(
                        determine_column_name(column_type),
                        sql_type,
                    ),
                )
    else:
        columns.append(
            Column(
                "value",
                db_backend.determine_sql_type_for_string_property(),
                nullable=False,
            ),
        )

    tables.append(
        Table(
            canonicalize_table_name(table_name + "_" + name),
            metadata,
            *columns,
            # removed to make sort algorithm work for mariadb
            # UniqueConstraint("id", "name"),
            schema=schema_name,
        ),
    )
    return tables


@add_method(EmbeddedObjectProperty)
def generate_table_information(self, name, db_backend, metadata, schema_name, table_name, is_extension=False, is_list=False, **kwargs):  # noqa: F811
    level = kwargs.get("level")
    return generate_object_table(
        self.type, db_backend, metadata, schema_name, table_name, is_extension, True, is_list,
        parent_table_name=table_name, level=level+1 if is_list else level,
    )


@add_method(EnumProperty)
def generate_table_information(self, name, db_backend, **kwargs):  # noqa: F811
    enum_re = "|".join(self.allowed)
    return Column(
        name,
        self.determine_sql_type(db_backend),
        db_backend.create_regex_constraint_expression(name, f"'^{enum_re}$'"),
        nullable=not self.required,
    )


@add_method(ExtensionsProperty)
def generate_table_information(self, name, db_backend, metadata, schema_name, table_name, **kwargs):  # noqa: F811
    columns = list()
    columns.append(
        Column(
            "id",
            db_backend.determine_sql_type_for_key_as_id(),
            ForeignKey(canonicalize_table_name(table_name, schema_name) + ".id", ondelete="CASCADE"),
            nullable=False,
        ),
    )
    columns.append(
        Column(
            "ext_table_name",
            db_backend.determine_sql_type_for_string_property(),
            nullable=False,
        ),
    )
    return [Table(canonicalize_table_name(table_name + "_" + name), metadata, *columns, schema=schema_name)]


@add_method(FloatProperty)
def generate_table_information(self, name, db_backend, **kwargs):  # noqa: F811
    return Column(
        name,
        self.determine_sql_type(db_backend),
        nullable=not self.required,
        default=self._fixed_value if hasattr(self, "_fixed_value") else None,
    )


@add_method(HashesProperty)
def generate_table_information(self, name, db_backend, metadata, schema_name, table_name, is_extension=False, **kwargs):  # noqa: F811
    level = kwargs.get("level")
    if kwargs.get("is_embedded_object"):
        if not kwargs.get("is_list") or level == 0:
            key_type = Text
        else:
            key_type = Integer
    else:
        key_type = Text
    return [
        create_hashes_table(
            name,
            metadata,
            db_backend,
            schema_name,
            table_name,
            key_type=key_type,
            level=level,
        ),
    ]


@add_method(HexProperty)
def generate_table_information(self, name, db_backend, **kwargs):  # noqa: F811
    return Column(
        name,
        db_backend.determine_sql_type_for_hex_property(),
        nullable=not self.required,
    )


@add_method(IDProperty)
def generate_table_information(self, name, db_backend, **kwargs):  # noqa: F811
    schema_name = kwargs.get('schema_name')
    table_name = kwargs.get("table_name")
    core_table = kwargs.get("core_table")
    id_req_exp = f"'^{table_name}" + "--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'"  # noqa: E131
    if schema_name:
        foreign_key_column = f"common.core_{core_table}.id"
    else:
        foreign_key_column = f"core_{core_table}.id"
    return Column(
        name,
        db_backend.determine_sql_type_for_key_as_id(),
        ForeignKey(foreign_key_column, ondelete="CASCADE"),
        db_backend.create_regex_constraint_expression(name, id_req_exp),
        primary_key=True,
        nullable=not (self.required),
    )


@add_method(IntegerProperty)
def generate_table_information(self, name, db_backend, **kwargs):  # noqa: F811
    return Column(
        name,
        self.determine_sql_type(db_backend),
        db_backend.create_min_max_constraint_expression(self, name),
        nullable=not self.required,
        default=self._fixed_value if hasattr(self, "_fixed_value") else None,
    )


@add_method(ListProperty)
def generate_table_information(self, name, db_backend, metadata, schema_name, table_name, **kwargs):  # noqa: F811
    is_extension = kwargs.get('is_extension')
    is_embedded_object = kwargs.get('is_embedded_object')
    tables = list()
    # handle more complex embedded object before deciding if the ARRAY type is usable
    if isinstance(self.contained, EmbeddedObjectProperty):
        columns = list()
        columns.append(
            Column(
                "id",
                db_backend.determine_sql_type_for_key_as_id(),
                ForeignKey(
                    canonicalize_table_name(table_name, schema_name) + ".id",
                    ondelete="CASCADE",
                ),
            ),
        )
        columns.append(
            Column(
                "ref_id",
                db_backend.determine_sql_type_for_key_as_int(),
                primary_key=True,
                nullable=False,
                # all such keys are generated using the global sequence.
                autoincrement=False,
            ),
        )
        tables.append(Table(canonicalize_table_name(table_name + "_" + name), metadata, *columns, schema=schema_name))
        tables.extend(
            self.contained.generate_table_information(
                name,
                db_backend,
                metadata,
                schema_name,
                canonicalize_table_name(table_name + "_" + name, None),
                # if sub_table_needed else canonicalize_table_name(table_name, None),
                is_extension,
                parent_table_name=table_name,
                is_list=True,
                level=kwargs.get("level"),
            ),
        )
        return tables
    elif isinstance(self.contained, ReferenceProperty):
        return [
            create_ref_table(
                metadata,
                db_backend,
                self.contained.specifics,
                canonicalize_table_name(table_name + "_" + name),
                canonicalize_table_name(table_name, schema_name) + ".id",
                schema_name,
            ),
        ]
    elif ((
        isinstance(
            self.contained,
            (BinaryProperty, BooleanProperty, StringProperty, IntegerProperty, FloatProperty, HexProperty, TimestampProperty),  # noqa: E131
        ) and
        not db_backend.array_allowed()
    ) or
          isinstance(self.contained, EnumProperty)):
        columns = list()
        if is_embedded_object:
            id_type = db_backend.determine_sql_type_for_key_as_int()
        else:
            id_type = db_backend.determine_sql_type_for_key_as_id()
        columns.append(
            Column(
                "id",
                id_type,
                ForeignKey(
                    canonicalize_table_name(table_name, schema_name) + ".id",
                    ondelete="CASCADE",
                ),
                nullable=False,
            ),
        )
        columns.append(self.contained.generate_table_information(name, db_backend))
        tables.append(Table(canonicalize_table_name(table_name + "_" + name), metadata, *columns, schema=schema_name))

    elif self.contained == KillChainPhase:
        tables.append(create_kill_chain_phases_table(name, metadata, db_backend, schema_name, table_name))
        return tables
    else:
        # if ARRAY is not allowed, it is handled by a previous if clause
        if isinstance(self.contained, Property):
            return create_array_column(name, self.contained.determine_sql_type(db_backend), not self.required)


def ref_column(name, specifics, db_backend, auth_type=0):
    if specifics:
        types = "|".join(specifics)
        if auth_type == 0:
            reg_ex = f"'^({types})" + "--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'"  # noqa: F811
            constraint = db_backend.create_regex_constraint_expression(name, reg_ex)
        else:
            reg_ex = "'--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$')"
            constraint = \
                db_backend.create_regex_constraint_and_expression(
                    (f"NOT({name}", f"'^({types})'"),
                    (name, reg_ex),
                )
        return Column(name, db_backend.determine_sql_type_for_reference_property(), constraint)  # , constraint)
    else:
        return Column(
            name,
            db_backend.determine_sql_type_for_reference_property(),
            nullable=False,
        )


@add_method(ObjectReferenceProperty)
def generate_table_information(self, name, db_backend, **kwargs):  # noqa: F811
    table_name = kwargs.get('table_name')
    raise ValueError(f"Property {name} in {table_name} is of type ObjectReferenceProperty, which is for STIX 2.0 only")


@add_method(ReferenceProperty)
def generate_table_information(self, name, db_backend, **kwargs):  # noqa: F811
    return ref_column(name, self.specifics, db_backend, self.auth_type)


@add_method(StringProperty)
def generate_table_information(self, name, db_backend, **kwargs):  # noqa: F811
    return Column(
        name,
        db_backend.determine_sql_type_for_string_property(),
        nullable=not self.required,
        default=self._fixed_value if hasattr(self, "_fixed_value") else None,
    )


@add_method(TimestampProperty)
def generate_table_information(self, name, db_backend, **kwargs):  # noqa: F811
    return Column(
        name,
        self.determine_sql_type(db_backend),
        nullable=not (self.required),
    )


@add_method(TypeProperty)
def generate_table_information(self, name, db_backend, **kwargs):  # noqa: F811
    return Column(
        name,
        db_backend.determine_sql_type_for_string_property(),
        nullable=not self.required,
        default=self._fixed_value if hasattr(self, "_fixed_value") else None,
    )

# =========================================================================


def generate_object_table(
    stix_object_class, db_backend, metadata, schema_name, foreign_key_name=None,
    is_extension=False, is_embedded_object=False, is_list=False, parent_table_name=None, level=0,
):
    properties = stix_object_class._properties
    if hasattr(stix_object_class, "_type"):
        table_name = stix_object_class._type
    else:
        table_name = stix_object_class.__name__
    # avoid long table names
    if table_name.startswith("extension-definition--"):
        # table_name = table_name[0:30]
        # table_name = table_name.replace("extension-definition-", "ext_def")
        table_name = shorten_extension_definition_id(table_name)
    if parent_table_name:
        table_name = parent_table_name + "_" + table_name
    core_properties = determine_core_properties(stix_object_class, is_embedded_object)
    columns = list()
    tables = list()
    if issubclass(stix_object_class, _Observable):
        core_table = "sco"
    else:
        # sro, smo common properties are the same as sdo's
        core_table = "sdo"
    for name, prop in properties.items():
        # type is never a column since it is implicit in the table
        if (name == 'id' or name not in core_properties) and name != 'type':
            col = prop.generate_table_information(
                name,
                db_backend,
                metadata=metadata,
                schema_name=schema_name,
                table_name=table_name,
                is_extension=is_extension,
                is_embedded_object=is_embedded_object,
                is_list=is_list,
                level=level,
                parent_table_name=parent_table_name,
                core_table=core_table,
            )
            if col is not None and isinstance(col, Column):
                columns.append(col)
            if col is not None and isinstance(col, list):
                tables.extend(col)
    if is_extension and not is_embedded_object:
        columns.append(
            Column(
                "id",
                db_backend.determine_sql_type_for_key_as_id(),
                # no Foreign Key because it could be for different tables
                primary_key=True,
            ),
        )
    if foreign_key_name:
        if level == 0:
            if is_extension and not is_embedded_object:
                column = Column(
                    "id",
                    db_backend.determine_sql_type_for_key_as_id(),
                    ForeignKey(
                        canonicalize_table_name(foreign_key_name, schema_name) + ".id",
                        ondelete="CASCADE",
                    ),
                )
            elif is_embedded_object:
                column = Column(
                    "id",
                    db_backend.determine_sql_type_for_key_as_int() if is_list else db_backend.determine_sql_type_for_key_as_id(),
                    ForeignKey(
                        canonicalize_table_name(foreign_key_name, schema_name) + (".ref_id" if is_list else ".id"),
                        ondelete="CASCADE",
                    ),
                    # if it is a not list, then it is a single embedded object, and the primary key is unique
                    primary_key=not is_list,
                )
        elif level > 0 and is_embedded_object:
            column = Column(
                "id",
                db_backend.determine_sql_type_for_key_as_int() if (is_embedded_object and is_list) else db_backend.determine_sql_type_for_key_as_id(),
                ForeignKey(
                    canonicalize_table_name(foreign_key_name, schema_name) + (".ref_id" if (is_embedded_object and is_list) else ".id"),
                    ondelete="CASCADE",
                ),
                primary_key=True,
                nullable=False,
            )
        else:
            column = Column(
                "id",
                db_backend.determine_sql_type_for_key_as_id(),
                ForeignKey(
                    canonicalize_table_name(foreign_key_name, schema_name) + ".id",
                    ondelete="CASCADE",
                ),
            )
        columns.append(column)

    all_tables = [Table(canonicalize_table_name(table_name), metadata, *columns, schema=schema_name)]
    all_tables.extend(tables)
    return all_tables


def add_tables(new_tables, tables):
    if isinstance(new_tables, list):
        tables.extend(new_tables)
    else:
        tables.append(new_tables)


def create_core_tables(metadata, db_backend):
    tables = list()
    add_tables(create_core_table(metadata, db_backend, "sdo"), tables)
    add_tables(create_granular_markings_table(metadata, db_backend, "sdo"), tables)
    add_tables(create_core_table(metadata, db_backend, "sco"), tables)
    add_tables(create_granular_markings_table(metadata, db_backend, "sco"), tables)
    add_tables(create_object_markings_refs_table(metadata, db_backend, "sdo"), tables)
    add_tables(create_object_markings_refs_table(metadata, db_backend, "sco"), tables)
    tables.extend(create_external_references_tables(metadata, db_backend))
    return tables


def create_table_objects(metadata, db_backend, stix_object_classes):
    if stix_object_classes:
        # If classes are given, allow some flexibility regarding lists of
        # classes vs single classes
        stix_object_classes = flat_classes(stix_object_classes)

    else:
        # If no classes given explicitly, discover them automatically
        stix_object_classes = get_stix_object_classes()

    tables = create_core_tables(metadata, db_backend)

    for stix_class in stix_object_classes:

        schema_name = db_backend.schema_for(stix_class)
        is_extension = issubclass(stix_class, _Extension)

        tables.extend(
            generate_object_table(
                stix_class,
                db_backend,
                metadata,
                schema_name,
                is_extension=is_extension,
            ),
        )

    return tables
