# from collections import OrderedDict

from sqlalchemy import (  # create_engine,; insert,
    ARRAY, TIMESTAMP, Boolean, CheckConstraint, Column, Float, ForeignKey,
    Integer, LargeBinary, Table, Text, UniqueConstraint,
)

from stix2.datastore.relational_db.add_method import add_method
from stix2.datastore.relational_db.utils import (
    SCO_COMMON_PROPERTIES, SDO_COMMON_PROPERTIES, canonicalize_table_name,
    determine_column_name, determine_sql_type_from_class, flat_classes,
    get_stix_object_classes, schema_for,
)
from stix2.properties import (
    BinaryProperty, BooleanProperty, DictionaryProperty,
    EmbeddedObjectProperty, EnumProperty, ExtensionsProperty, FloatProperty,
    HashesProperty, HexProperty, IDProperty, IntegerProperty, ListProperty,
    ObjectReferenceProperty, Property, ReferenceProperty, StringProperty,
    TimestampProperty, TypeProperty,
)
from stix2.v21.base import _Extension
from stix2.v21.common import KillChainPhase


def aux_table_property(prop, name, core_properties):
    if isinstance(prop, ListProperty) and name not in core_properties:
        contained_property = prop.contained
        return not isinstance(contained_property, (StringProperty, IntegerProperty, FloatProperty))
    elif isinstance(prop, DictionaryProperty) and name not in core_properties:
        return True
    else:
        return False


def derive_column_name(prop):
    contained_property = prop.contained
    if isinstance(contained_property, ReferenceProperty):
        return "ref_id"
    elif isinstance(contained_property, StringProperty):
        return "value"


def create_object_markings_refs_table(metadata, sco_or_sdo):
    return create_ref_table(
        metadata,
        {"marking-definition"},
        "object_marking_refs_" + sco_or_sdo,
        "common.core_" + sco_or_sdo + ".id",
        "common",
        0,
    )


def create_ref_table(metadata, specifics, table_name, foreign_key_name, schema_name, auth_type=0):
    columns = list()
    columns.append(
        Column(
            "id",
            Text,
            ForeignKey(
                foreign_key_name,
                ondelete="CASCADE",
            ),
            nullable=False,
        ),
    )
    columns.append(ref_column("ref_id", specifics, auth_type))
    return Table(table_name, metadata, *columns, schema=schema_name)


def create_hashes_table(name, metadata, schema_name, table_name, key_type=Text, level=1):
    columns = list()
    # special case, perhaps because its a single embedded object with hashes, and not a list of embedded object
    # making the parent table's primary key does seem to worl

    columns.append(
        Column(
            "id",
            key_type,
            ForeignKey(
                canonicalize_table_name(table_name, schema_name) + (".hash_ref_id" if table_name == "external_references" else ".id"),
                ondelete="CASCADE",
            ),

            nullable=False,
        ),
    )
    columns.append(
        Column(
            "hash_name",
            Text,
            nullable=False,
        ),
    )
    columns.append(
        Column(
            "hash_value",
            Text,
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


def create_kill_chain_phases_table(name, metadata, schema_name, table_name):
    columns = list()
    columns.append(
        Column(
            "id",
            Text,
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
            Text,
            nullable=False,
        ),
    )
    columns.append(
        Column(
            "phase_name",
            Text,
            nullable=False,
        ),
    )
    return Table(canonicalize_table_name(table_name + "_" + name), metadata, *columns, schema=schema_name)


def create_granular_markings_table(metadata, sco_or_sdo):
    return Table(
        "granular_marking_" + sco_or_sdo,
        metadata,
        Column(
            "id",
            Text,
            ForeignKey("common.core_" + sco_or_sdo + ".id", ondelete="CASCADE"),
            nullable=False,
        ),
        Column("lang", Text),
        Column(
            "marking_ref",
            Text,
            CheckConstraint(
                "marking_ref ~ '^marking-definition--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'",  # noqa: E131
            ),
        ),
        Column(
            "selectors",
            ARRAY(Text),
            CheckConstraint("array_length(selectors, 1) IS NOT NULL"),
            nullable=False,
        ),
        CheckConstraint(
            """(lang IS NULL AND marking_ref IS NOT NULL)
               OR
               (lang IS NOT NULL AND marking_ref IS NULL)""",
        ),
        schema="common",
    )


def create_external_references_tables(metadata):
    columns = [
        Column(
            "id",
            Text,
            ForeignKey("common.core_sdo" + ".id", ondelete="CASCADE"),
            CheckConstraint(
                "id ~ '^[a-z][a-z0-9-]+[a-z0-9]--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'",  # noqa: E131
            ),
        ),
        Column("source_name", Text),
        Column("description", Text),
        Column("url", Text),
        Column("external_id", Text),
        # all such keys are generated using the global sequence.
        Column("hash_ref_id", Integer, primary_key=True, autoincrement=False),
    ]
    return [
        Table("external_references", metadata, *columns, schema="common"),
        create_hashes_table("hashes", metadata, "common", "external_references", Integer),
    ]


def create_core_table(metadata, schema_name):
    columns = [
        Column(
            "id",
            Text,
            CheckConstraint(
                "id ~ '^[a-z][a-z0-9-]+[a-z0-9]--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'",  # noqa: E131
            ),
            primary_key=True,
        ),
        Column("spec_version", Text, default="2.1"),
    ]
    if schema_name == "sdo":
        sdo_columns = [
            Column(
                "created_by_ref",
                Text,
                CheckConstraint(
                    "created_by_ref ~ '^identity--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'",   # noqa: E131
                ),
            ),
            Column("created", TIMESTAMP(timezone=True)),
            Column("modified", TIMESTAMP(timezone=True)),
            Column("revoked", Boolean),
            Column("confidence", Integer),
            Column("lang", Text),
            Column("labels", ARRAY(Text)),
        ]
        columns.extend(sdo_columns)
    else:
        columns.append(Column("defanged", Boolean, default=False)),
    return Table(
        "core_" + schema_name,
        metadata,
        *columns,
        schema="common",
    )


@add_method(Property)
def determine_sql_type(self):  # noqa: F811
    pass


@add_method(KillChainPhase)
def determine_sql_type(self):  # noqa: F811
    return None


@add_method(BinaryProperty)
def determine_sql_type(self):  # noqa: F811
    return Boolean


@add_method(BooleanProperty)
def determine_sql_type(self):  # noqa: F811
    return Boolean


@add_method(FloatProperty)
def determine_sql_type(self):  # noqa: F811
    return Float


@add_method(HexProperty)
def determine_sql_type(self):  # noqa: F811
    return LargeBinary


@add_method(IntegerProperty)
def determine_sql_type(self):  # noqa: F811
    return Integer


@add_method(ReferenceProperty)
def determine_sql_type(self):  # noqa: F811
    return Text


@add_method(StringProperty)
def determine_sql_type(self):  # noqa: F811
    return Text


@add_method(TimestampProperty)
def determine_sql_type(self):  # noqa: F811
    return TIMESTAMP(timezone=True)


# ----------------------------- generate_table_information methods ----------------------------

@add_method(KillChainPhase)
def generate_table_information(  # noqa: F811
        self, name, metadata, schema_name, table_name, is_extension=False, is_list=False,
        **kwargs,
):
    level = kwargs.get("level")
    return generate_object_table(
        self.type, metadata, schema_name, table_name, is_extension, True, is_list,
        parent_table_name=table_name, level=level + 1 if is_list else level,
    )


@add_method(Property)
def generate_table_information(self, name, **kwargs):   # noqa: F811
    pass


@add_method(BinaryProperty)
def generate_table_information(self, name, **kwargs):  # noqa: F811
    return Column(
        name,
        Text,
        CheckConstraint(
            # this regular expression might accept or reject some legal base64 strings
            f"{name} ~  " + "'^[-A-Za-z0-9+/]*={0,3}$'",
        ),
        nullable=not self.required,
    )


@add_method(BooleanProperty)
def generate_table_information(self, name, **kwargs):  # noqa: F811
    return Column(
        name,
        Boolean,
        nullable=not self.required,
        default=self._fixed_value if hasattr(self, "_fixed_value") else None,
    )


@add_method(DictionaryProperty)
def generate_table_information(self, name, metadata, schema_name, table_name, is_extension=False, **kwargs):  # noqa: F811
    columns = list()

    columns.append(
        Column(
            "id",
            Text,
            ForeignKey(canonicalize_table_name(table_name, schema_name) + ".id", ondelete="CASCADE"),
        ),
    )
    columns.append(
        Column(
            "name",
            Text,
            nullable=False,
        ),
    )
    if len(self.valid_types) == 1:
        if not isinstance(self.valid_types[0], ListProperty):
            columns.append(
                Column(
                    "value",
                    # its a class
                    determine_sql_type_from_class(self.valid_types[0]),
                    nullable=False,
                ),
            )
        else:
            contained_class = self.valid_types[0].contained
            columns.append(
                Column(
                    "value",
                    # its an instance, not a class
                    ARRAY(contained_class.determine_sql_type()),
                    nullable=False,
                ),
            )
    else:
        for column_type in self.valid_types:
            sql_type = determine_sql_type_from_class(column_type)
            columns.append(
                Column(
                    determine_column_name(column_type),
                    sql_type,
                ),
            )
    return [
        Table(
            canonicalize_table_name(table_name + "_" + name),
            metadata,
            *columns,
            UniqueConstraint("id", "name"),
            schema=schema_name,
        ),
    ]


@add_method(EmbeddedObjectProperty)
def generate_table_information(self, name, metadata, schema_name, table_name, is_extension=False, is_list=False, **kwargs):  # noqa: F811
    level = kwargs.get("level")
    return generate_object_table(
        self.type, metadata, schema_name, table_name, is_extension, True, is_list,
        parent_table_name=table_name, level=level+1 if is_list else level,
    )


@add_method(EnumProperty)
def generate_table_information(self, name, **kwargs):  # noqa: F811
    enum_re = "|".join(self.allowed)
    return Column(
        name,
        Text,
        CheckConstraint(
            f"{name} ~ '^{enum_re}$'",
        ),
        nullable=not self.required,
    )


@add_method(ExtensionsProperty)
def generate_table_information(self, name, metadata, schema_name, table_name, **kwargs):  # noqa: F811
    columns = list()
    columns.append(
        Column(
            "id",
            Text,
            ForeignKey(canonicalize_table_name(table_name, schema_name) + ".id", ondelete="CASCADE"),
            nullable=False,
        ),
    )
    columns.append(
        Column(
            "ext_table_name",
            Text,
            nullable=False,
        ),
    )
    return [Table(canonicalize_table_name(table_name + "_" + name), metadata, *columns, schema=schema_name)]


@add_method(FloatProperty)
def generate_table_information(self, name, **kwargs):  # noqa: F811
    return Column(
        name,
        Float,
        nullable=not self.required,
        default=self._fixed_value if hasattr(self, "_fixed_value") else None,
    )


@add_method(HashesProperty)
def generate_table_information(self, name, metadata, schema_name, table_name, is_extension=False, **kwargs):  # noqa: F811
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
            schema_name,
            table_name,
            key_type=key_type,
            level=level,
        ),
    ]


@add_method(HexProperty)
def generate_table_information(self, name, **kwargs):  # noqa: F811
    return Column(
        name,
        LargeBinary,
        nullable=not self.required,
    )


@add_method(IDProperty)
def generate_table_information(self, name, **kwargs):  # noqa: F811
    schema_name = kwargs.get('schema_name')
    if schema_name == "sro":
        # sro common properties are the same as sdo's
        schema_name = "sdo"
    table_name = kwargs.get("table_name")
    if schema_name == "common":
        return Column(
            name,
            Text,
            CheckConstraint(
                f"{name} ~ '^{table_name}" + "--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'",
                # noqa: E131
            ),
            primary_key=True,
            nullable=not (self.required),
        )
    else:
        foreign_key_column = f"common.core_{schema_name}.id"
        return Column(
            name,
            Text,
            ForeignKey(foreign_key_column, ondelete="CASCADE"),
            CheckConstraint(
                f"{name} ~ '^{table_name}" + "--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'",
                # noqa: E131
            ),
            primary_key=True,
            nullable=not (self.required),
        )

    return Column(
        name,
        Text,
        ForeignKey(foreign_key_column, ondelete="CASCADE"),
        CheckConstraint(
            f"{name} ~ '^{table_name}" + "--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'",  # noqa: E131
        ),
        primary_key=True,
        nullable=not (self.required),
    )


@add_method(IntegerProperty)
def generate_table_information(self, name, **kwargs):  # noqa: F811
    return Column(
        name,
        Integer,
        nullable=not self.required,
        default=self._fixed_value if hasattr(self, "_fixed_value") else None,
    )


@add_method(ListProperty)
def generate_table_information(self, name, metadata, schema_name, table_name, **kwargs):  # noqa: F811
    is_extension = kwargs.get('is_extension')
    tables = list()
    if isinstance(self.contained, ReferenceProperty):
        return [
            create_ref_table(
                metadata,
                self.contained.specifics,
                canonicalize_table_name(table_name + "_" + name),
                canonicalize_table_name(table_name, schema_name) + ".id",
                schema_name,
            ),
        ]
    elif isinstance(self.contained, EnumProperty):
        columns = list()
        columns.append(
            Column(
                "id",
                Text,
                ForeignKey(
                    canonicalize_table_name(table_name, schema_name) + ".id",
                    ondelete="CASCADE",
                ),
                nullable=False,
            ),
        )
        columns.append(self.contained.generate_table_information(name))
        tables.append(Table(canonicalize_table_name(table_name + "_" + name), metadata, *columns, schema=schema_name))
    elif isinstance(self.contained, EmbeddedObjectProperty):
        columns = list()
        columns.append(
            Column(
                "id",
                Text,
                ForeignKey(
                    canonicalize_table_name(table_name, schema_name) + ".id",
                    ondelete="CASCADE",
                ),
            ),
        )
        columns.append(
            Column(
                "ref_id",
                Integer,
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
                metadata,
                schema_name,
                canonicalize_table_name(table_name + "_" + name, None),  # if sub_table_needed else canonicalize_table_name(table_name, None),
                is_extension,
                parent_table_name=table_name,
                is_list=True,
                level=kwargs.get("level"),
            ),
        )
        return tables
    elif self.contained == KillChainPhase:
        tables.append(create_kill_chain_phases_table(name, metadata, schema_name, table_name))
        return tables
    else:
        if isinstance(self.contained, Property):
            sql_type = self.contained.determine_sql_type()
            if sql_type:
                return Column(
                    name,
                    ARRAY(sql_type),
                    nullable=not (self.required),
                )


def ref_column(name, specifics, auth_type=0):
    if specifics:
        types = "|".join(specifics)
        if auth_type == 0:
            constraint = \
                CheckConstraint(
                    f"{name} ~ '^({types})" +
                    "--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'",
                )
        else:
            constraint = \
                CheckConstraint(
                    f"(NOT({name} ~ '^({types})')) AND ({name} ~ " +
                    "'--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$')",
                )
        return Column(name, Text, constraint)
    else:
        return Column(
            name,
            Text,
            nullable=False,
        )


@add_method(ObjectReferenceProperty)
def generate_table_information(self, name, **kwargs):  # noqa: F811
    table_name = kwargs.get('table_name')
    raise ValueError(f"Property {name} in {table_name} is of type ObjectReferenceProperty, which is for STIX 2.0 only")


@add_method(ReferenceProperty)
def generate_table_information(self, name, **kwargs):  # noqa: F811
    return ref_column(name, self.specifics, self.auth_type)


@add_method(StringProperty)
def generate_table_information(self, name, **kwargs):  # noqa: F811
    return Column(
        name,
        Text,
        nullable=not self.required,
        default=self._fixed_value if hasattr(self, "_fixed_value") else None,
    )


@add_method(TimestampProperty)
def generate_table_information(self, name, **kwargs):  # noqa: F811
    return Column(
        name,
        TIMESTAMP(timezone=True),
        # CheckConstraint(
        #     f"{name} ~ '^{enum_re}$'"
        # ),
        nullable=not (self.required),
    )


@add_method(TypeProperty)
def generate_table_information(self, name, **kwargs):  # noqa: F811
    return Column(
        name,
        Text,
        nullable=not self.required,
        default=self._fixed_value if hasattr(self, "_fixed_value") else None,
    )


def generate_object_table(
    stix_object_class, metadata, schema_name, foreign_key_name=None,
    is_extension=False, is_embedded_object=False, is_list=False, parent_table_name=None, level=0,
):
    properties = stix_object_class._properties
    if hasattr(stix_object_class, "_type"):
        table_name = stix_object_class._type
    else:
        table_name = stix_object_class.__name__
    # avoid long table names
    if table_name.startswith("extension-definition"):
        table_name = table_name[0:30]
        table_name = table_name.replace("extension-definition-", "ext_def")
    if parent_table_name:
        table_name = parent_table_name + "_" + table_name
    if is_embedded_object:
        core_properties = list()
    elif schema_name in ["sdo", "sro"]:
        core_properties = SDO_COMMON_PROPERTIES
    elif schema_name == "sco":
        core_properties = SCO_COMMON_PROPERTIES
    else:
        core_properties = list()
    columns = list()
    tables = list()
    for name, prop in properties.items():
        # type is never a column since it is implicit in the table
        if (name == 'id' or name not in core_properties) and name != 'type':
            col = prop.generate_table_information(
                name,
                metadata=metadata,
                schema_name=schema_name,
                table_name=table_name,
                is_extension=is_extension,
                is_embedded_object=is_embedded_object,
                is_list=is_list,
                level=level,
                parent_table_name=parent_table_name,
            )
            if col is not None and isinstance(col, Column):
                columns.append(col)
            if col is not None and isinstance(col, list):
                tables.extend(col)
    if is_extension and not is_embedded_object:
        columns.append(
            Column(
                "id",
                Text,
                # no Foreign Key because it could be for different tables
                primary_key=True,
            ),
        )
    if foreign_key_name:
        if level == 0:
            if is_extension and not is_embedded_object:
                column = Column(
                    "id",
                    Text,
                    ForeignKey(
                        canonicalize_table_name(foreign_key_name, schema_name) + ".id",
                        ondelete="CASCADE",
                    ),
                )
            elif is_embedded_object:
                column = Column(
                    "id",
                    Integer if is_list else Text,
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
                Integer if (is_embedded_object and is_list) else Text,
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
                Text,
                ForeignKey(
                    canonicalize_table_name(foreign_key_name, schema_name) + ".id",
                    ondelete="CASCADE",
                ),
            )
        columns.append(column)

    # all_tables = [Table(canonicalize_table_name(table_name), metadata, *columns, schema=schema_name)]
    # all_tables.extend(tables)
    # return all_tables

    tables.append(Table(canonicalize_table_name(table_name), metadata, *columns, schema=schema_name))
    return tables


def create_core_tables(metadata):
    tables = [
        create_core_table(metadata, "sdo"),
        create_granular_markings_table(metadata, "sdo"),
        create_core_table(metadata, "sco"),
        create_granular_markings_table(metadata, "sco"),
        create_object_markings_refs_table(metadata, "sdo"),
        create_object_markings_refs_table(metadata, "sco"),
    ]
    tables.extend(create_external_references_tables(metadata))
    return tables


def create_table_objects(metadata, stix_object_classes):
    if stix_object_classes:
        # If classes are given, allow some flexibility regarding lists of
        # classes vs single classes
        stix_object_classes = flat_classes(stix_object_classes)

    else:
        # If no classes given explicitly, discover them automatically
        stix_object_classes = get_stix_object_classes()

    tables = create_core_tables(metadata)

    for stix_class in stix_object_classes:

        schema_name = schema_for(stix_class)
        is_extension = issubclass(stix_class, _Extension)

        tables.extend(
            generate_object_table(
                stix_class,
                metadata,
                schema_name,
                is_extension=is_extension,
            ),
        )

    return tables
