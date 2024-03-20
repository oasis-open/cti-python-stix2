# from collections import OrderedDict

from sqlalchemy import (  # create_engine,; insert,
    ARRAY, TIMESTAMP, Boolean, CheckConstraint, Column, Float, ForeignKey,
    Integer, LargeBinary, Table, Text,
)

from stix2.properties import (
    BinaryProperty, BooleanProperty, DictionaryProperty,
    EmbeddedObjectProperty, EnumProperty, ExtensionsProperty, FloatProperty,
    HashesProperty, HexProperty, IDProperty, IntegerProperty, ListProperty,
    ObjectReferenceProperty, Property, ReferenceProperty, StringProperty,
    TimestampProperty, TypeProperty,
)
from stix2.v21.common import KillChainPhase

# Helps us know which data goes in core, and which in a type-specific table.
SCO_COMMON_PROPERTIES = {
    "id",
    # "type",
    "spec_version",
    "object_marking_refs",
    "granular_markings",
    "defanged",
}


# Helps us know which data goes in core, and which in a type-specific table.
SDO_COMMON_PROPERTIES = {
    "id",
    # "type",
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
    "external_references",
}


def canonicalize_table_name(table_name, is_sdo):
    if is_sdo:
        full_name = ("sdo" if is_sdo else "sco") + "." + table_name
    else:
        full_name = table_name
    return full_name.replace("-", "_")


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


def create_granular_markings_table(metadata, sco_or_sdo):
    return Table(
        "common.granular_marking_" + sco_or_sdo,
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
                "marking_ref ~ '^marking-definition--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'",
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
    )


def create_core_table(metadata, sco_or_sdo):
    columns = [
        Column(
            "id",
            Text,
            CheckConstraint(
                "id ~ '^[a-z][a-z0-9-]+[a-z0-9]--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'",
                # noqa: E131
            ),
            primary_key=True,
        ),
        Column("spec_version", Text, default="2.1"),
        Column("object_marking_ref", ARRAY(Text)),
    ]
    if sco_or_sdo == "sdo":
        sdo_columns = [
            Column(
                "created_by_ref",
                Text,
                CheckConstraint(
                    "created_by_ref ~ '^identity--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'",
                    # noqa: E131
                ),
            ),
            Column("created", TIMESTAMP(timezone=True)),
            Column("modified", TIMESTAMP(timezone=True)),
            Column("revoked", Boolean),
            Column("confidence", Integer),
            Column("lang", Text),
        ]
        columns.extend(sdo_columns)
    else:
        columns.append(Column("defanged", Boolean, default=False)),
    return Table(
        "common.core_" + sco_or_sdo,
        metadata,
        *columns
    )


# _ALLOWABLE_CLASSES = get_all_subclasses(_STIXBase21)
#
#
# _ALLOWABLE_CLASSES.extend(get_all_subclasses(Property))


def create_real_method_name(name, klass_name):
    # if klass_name not in _ALLOWABLE_CLASSES:
    #     raise NameError
    # split_up_klass_name = re.findall('[A-Z][^A-Z]*', klass_name)
    # split_up_klass_name.remove("Type")
    return name + "_" + "_".join([x.lower() for x in klass_name])


def add_method(cls):
    def decorator(fn):
        method_name = fn.__name__
        fn.__name__ = create_real_method_name(fn.__name__, cls.__name__)
        setattr(cls, method_name, fn)
        return fn
    return decorator


@add_method(KillChainPhase)
def determine_sql_type(self):
    return None


@add_method(Property)
def generate_table_information(self, metadata, name, is_sdo, table_name, is_extension=False):
    pass


@add_method(Property)
def determine_sql_type(self):  # noqa: F811
    pass


@add_method(StringProperty)
def generate_table_information(self, metadata, name, is_sdo, table_name, is_extension=False):  # noqa: F811
    return Column(
        name,
        Text,
        nullable=not(self.required),
        default=self._fixed_value if hasattr(self, "_fixed_value") else None,
    )


@add_method(StringProperty)
def determine_sql_type(self):  # noqa: F811
    return Text


@add_method(IntegerProperty)
def generate_table_information(self, metadata, name, is_sdo, table_name, is_extension=False):  # noqa: F811
    return Column(
        name,
        Integer,
        nullable=not(self.required),
        default=self._fixed_value if hasattr(self, "_fixed_value") else None,
    )


@add_method(IntegerProperty)
def determine_sql_type(self):  # noqa: F811
    return Integer


@add_method(FloatProperty)
def generate_table_information(self, metadata, name, is_sdo, table_name, is_extension=False):  # noqa: F811
    return Column(
        name,
        Float,
        nullable=not(self.required),
        default=self._fixed_value if hasattr(self, "_fixed_value") else None,
    )


@add_method(FloatProperty)
def determine_sql_type(self):  # noqa: F811
    return Float


@add_method(BooleanProperty)
def generate_table_information(self, metadata, name, is_sdo, table_name, is_extension=False):  # noqa: F811
    return Column(
        name,
        Boolean,
        nullable=not(self.required),
        default=self._fixed_value if hasattr(self, "_fixed_value") else None,
    )


@add_method(BooleanProperty)
def determine_sql_type(self):  # noqa: F811
    return Boolean


@add_method(TypeProperty)
def generate_table_information(self, metadata, name, is_sdo, table_name, is_extension=False):  # noqa: F811
    return Column(
        name,
        Text,
        nullable=not(self.required),
        default=self._fixed_value if hasattr(self, "_fixed_value") else None,
    )


@add_method(IDProperty)
def generate_table_information(self, metadata, name, is_sdo, table_name, is_extension=False):  # noqa: F811
    foreign_key_column = "common.core_sdo.id" if is_sdo else "common.core_sco.id"
    return Column(
        name,
        Text,
        ForeignKey(foreign_key_column, ondelete="CASCADE"),
        CheckConstraint(
            f"{name} ~ '^{table_name}--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'",  # noqa: E131
        ),
        primary_key=True,
        nullable=not (self.required),
    )


@add_method(EnumProperty)
def generate_table_information(self, metadata, name, is_sdo, table_name, is_extension=False):  # noqa: F811
    enum_re = "|".join(self.allowed)
    return Column(
        name,
        Text,
        CheckConstraint(
            f"{name} ~ '^{enum_re}$'",
        ),
        nullable=not (self.required),
    )


@add_method(TimestampProperty)
def generate_table_information(self, metadata, name, is_sdo, table_name, is_extension=False):  # noqa: F811
    return Column(
        name,
        TIMESTAMP(timezone=True),
        # CheckConstraint(
        #     f"{name} ~ '^{enum_re}$'"
        # ),
        nullable=not (self.required),
    )


@add_method(DictionaryProperty)
def generate_table_information(self, metadata, name, is_sdo, table_name, is_extension=False):  # noqa: F811
    columns = list()

    columns.append(
        Column(
            "id",
            Integer if is_extension else Text,
            ForeignKey(canonicalize_table_name(table_name, is_sdo) + ".id", ondelete="CASCADE"),
            primary_key=True,
        ),
    )
    columns.append(
        Column(
            "name",
            Text,
            nullable=False,
        ),
    )
    if len(self.specifics) == 1:
        if self.specifics[0] != "string_list":
            columns.append(
                Column(
                    "value",
                    Text if self.specifics[0] == "string" else Integer,
                    nullable=False,
                ),
            )
        else:
            columns.append(
                Column(
                    "value",
                    ARRAY(Text),
                    nullable=False,
                ),
            )
    else:
        columns.append(
            Column(
                "string_value",
                Text,
            ),
        )
        columns.append(
            Column(
                "integer_value",
                Integer,
            ),
        )
    return [Table(canonicalize_table_name(table_name + "_" + name, is_sdo), metadata, *columns)]


@add_method(HashesProperty)
def generate_table_information(self, metadata, name, is_sdo, table_name, is_extension=False):  # noqa: F811

    columns = list()
    columns.append(
        Column(
            "id",
            Integer if is_extension else Text,
            ForeignKey(
                canonicalize_table_name(table_name, is_sdo) + ".id",
                ondelete="CASCADE",
            ),
            primary_key=True,
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
    return [Table(canonicalize_table_name(table_name + "_" + name, is_sdo), metadata, *columns)]


@add_method(HexProperty)
def generate_table_information(self, metadata, name, is_sdo, table_name, is_extension=False):  # noqa: F811
    return Column(
        name,
        LargeBinary,
        nullable=not (self.required),
    )


@add_method(BinaryProperty)
def generate_table_information(self, metadata, name, is_sdo, table_name, is_extension=False):  # noqa: F811
    print("BinaryProperty not handled, yet")
    return None


@add_method(ExtensionsProperty)
def generate_table_information(self, metadata, name, is_sdo, table_name, is_extension=False):  # noqa: F811
    columns = list()
    columns.append(
        Column(
            "id",
            Text,
            ForeignKey(canonicalize_table_name(table_name, is_sdo) + ".id", ondelete="CASCADE"),
            primary_key=True,
        ),
    )
    columns.append(
        Column(
            "ext_table_name",
            Text,
            nullable=False,
        ),
    )
    columns.append(
        Column(
            "ext_table_id",
            Integer,
            nullable=False,
        ),
    )
    return [Table(canonicalize_table_name(table_name + "_" + name, is_sdo), metadata, *columns)]


def ref_column(name, specifics):
    if specifics:
        allowed_types = "|".join(specifics)
        return Column(
            name,
            Text,
            CheckConstraint(
                f"{name} ~ '^({allowed_types})--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'",  # noqa: E131
            ),
        )
    else:
        return Column(
            name,
            Text,
            nullable=False,
        )


@add_method(ReferenceProperty)
def generate_table_information(self, metadata, name, is_sdo, table_name, is_extension=False):  # noqa: F811
    return ref_column(name, self.specifics)


@add_method(EmbeddedObjectProperty)
def generate_table_information(self, metadata, name, is_sdo, table_name, is_extension=False):  # noqa: F811
    return generate_object_table(self.type, metadata, is_sdo, table_name, is_extension)


@add_method(ObjectReferenceProperty)
def generate_table_information(self, metadata, name, is_sdo, table_name, is_extension=False):  # noqa: F811
    raise ValueError(f"Property {name} in {table_name} is of type ObjectReferenceProperty, which is for STIX 2.0 only")


@add_method(ListProperty)
def generate_table_information(self, metadata, name, is_sdo, table_name, is_extension=False):  # noqa: F811
    tables = list()
    if isinstance(self.contained, ReferenceProperty):
        columns = list()
        columns.append(
            Column(
                "id",
                Integer if is_extension else Text,
                ForeignKey(
                    canonicalize_table_name(table_name, is_sdo) + ".id",
                    ondelete="CASCADE",
                ),
                primary_key=True,
            ),
        )
        columns.append(ref_column("ref_id", self.contained.specifics))
        return [Table(canonicalize_table_name(table_name + "_" + name, is_sdo), metadata, *columns)]
    elif isinstance(self.contained, EmbeddedObjectProperty):
        columns = list()
        columns.append(
            Column(
                "id",
                Integer if is_extension else Text,
                ForeignKey(
                    canonicalize_table_name(table_name, is_sdo) + ".id",
                    ondelete="CASCADE",
                ),
                primary_key=True,
            ),
        )
        columns.append(
            Column(
                "ref_id",
                Integer if is_extension else Text,
                nullable=False,
            ),
        )
        tables.append(Table(canonicalize_table_name(table_name + "_" + name, is_sdo), metadata, *columns))
        tables.extend(
            self.contained.generate_table_information(
                metadata,
                name,
                False,
                canonicalize_table_name(table_name + "_" + name, None),
            ),
        )
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


def generate_object_table(stix_object_class, metadata, is_sdo, foreign_key_name=None, is_extension=False):
    properties = stix_object_class._properties
    if hasattr(stix_object_class, "_type"):
        table_name = stix_object_class._type
    else:
        table_name = stix_object_class.__name__
    core_properties = SDO_COMMON_PROPERTIES if is_sdo else SCO_COMMON_PROPERTIES
    columns = list()
    tables = list()
    for name, prop in properties.items():
        if name == 'id' or name not in core_properties:
            col = prop.generate_table_information(metadata, name, is_sdo, table_name, is_extension=is_extension)
            if col is not None and isinstance(col, Column):
                columns.append(col)
            if col is not None and isinstance(col, list):
                tables.extend(col)
    if is_extension:
        columns.append(
            Column(
                "id",
                Integer,
                # no Foreign Key because it could be for different tables
                primary_key=True,
            ),
        )
    if foreign_key_name:
        columns.append(
            Column(
                "id",
                Text,
                ForeignKey(
                    canonicalize_table_name(foreign_key_name, is_sdo) + ".id",
                    ondelete="CASCADE",
                ),
                primary_key=True,
            ),
        )
        return [Table(canonicalize_table_name(table_name, is_sdo), metadata, *columns)]
    else:
        all_tables = [Table(canonicalize_table_name(table_name, is_sdo), metadata, *columns)]
        all_tables.extend(tables)
        return all_tables


def create_core_tables(metadata):
    return [
        create_core_table(metadata, "sdo"),
        create_granular_markings_table(metadata, "sdo"),
        create_core_table(metadata, "sco"),
        create_granular_markings_table(metadata, "sco"),
    ]
