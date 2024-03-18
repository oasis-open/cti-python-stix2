# from collections import OrderedDict

from sqlalchemy import (  # create_engine,; insert,
    ARRAY, TIMESTAMP, Boolean, CheckConstraint, Column, Float, ForeignKey,
    Integer, LargeBinary, MetaData, Table, Text,
)
from sqlalchemy.schema import CreateTable

from stix2.properties import (
    BinaryProperty, BooleanProperty, DictionaryProperty,
    EmbeddedObjectProperty, EnumProperty, ExtensionsProperty, FloatProperty,
    HashesProperty, HexProperty, IDProperty, IntegerProperty, ListProperty,
    ObjectReferenceProperty, Property, ReferenceProperty, StringProperty,
    TimestampProperty, TypeProperty,
)
from stix2.v21.common import KillChainPhase

metadata = MetaData()


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


def canonicalize_table_name_with_schema(schema_name, table_name):
    full_name = schema_name + "." + table_name
    return full_name.replace("-", "_")


def canonicalize_table_name(table_name):
    return table_name.replace("-", "_")


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


def get_all_subclasses(cls):
    all_subclasses = []

    for subclass in cls.__subclasses__():
        all_subclasses.append(subclass)
        all_subclasses.extend(get_all_subclasses(subclass))

    return all_subclasses


def create_core_sdo_table():
    x = Table(
        "core_sdo",
        metadata,
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
        Column(
            "created_by_ref",
            Text,
            CheckConstraint(
                "created_by_ref ~ ^identity--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$",
                # noqa: E131
            ),
        ),
        Column("created", TIMESTAMP(timezone=True)),
        Column("modified", TIMESTAMP(timezone=True)),
        Column("revoked", Boolean),
        Column("confidence", Integer),
        Column("lang", Text),
        Column("object_marking_ref", ARRAY(Text)),
        schema="common",
    )
    print(CreateTable(x))


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
def generate_table_information(self, name, is_sdo, table_name):
    pass


@add_method(Property)
def determine_sql_type(self):  # noqa: F811
    pass


@add_method(StringProperty)
def generate_table_information(self, name, is_sdo, table_name):  # noqa: F811
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
def generate_table_information(self, name, is_sdo, table_name):  # noqa: F811
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
def generate_table_information(self, name, is_sdo, table_name):  # noqa: F811
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
def generate_table_information(self, name, is_sdo, table_name):  # noqa: F811
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
def generate_table_information(self, name, is_sdo, table_name):  # noqa: F811
    return Column(
        name,
        Text,
        nullable=not(self.required),
        default=self._fixed_value if hasattr(self, "_fixed_value") else None,
    )


@add_method(IDProperty)
def generate_table_information(self, name, is_sdo, table_name):  # noqa: F811
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
def generate_table_information(self, name, is_sdo, table_name):  # noqa: F811
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
def generate_table_information(self, name, is_sdo, table_name):  # noqa: F811
    return Column(
        name,
        TIMESTAMP(timezone=True),
        # CheckConstraint(
        #     f"{name} ~ '^{enum_re}$'"
        # ),
        nullable=not (self.required),
    )


@add_method(DictionaryProperty)
def generate_table_information(self, name, is_sdo, table_name):  # noqa: F811
    columns = list()
    columns.append(
        Column(
            "id",
            Text,
            ForeignKey(canonicalize_table_name(table_name), ondelete="CASCADE"),
        ),
    )
    columns.append(
        Column(
            "name",
            Text,
            nullable=False,
        ),
    )
    columns.append(
        Column(
            "value",
            Text,
            nullable=False,
        ),
    )
    return Table(canonicalize_table_name(table_name + "_" + name), metadata, *columns)


@add_method(HashesProperty)
def generate_table_information(self, name, is_sdo, table_name):  # noqa: F811

    columns = list()
    columns.append(
        Column(
            "id",
            Text,
            ForeignKey(
                canonicalize_table_name(table_name),
                ondelete="CASCADE",
            ),
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
    return Table(canonicalize_table_name(table_name + "_" + name), metadata, *columns)


@add_method(HexProperty)
def generate_table_information(self, name, is_sdo, table_name):  # noqa: F811
    return Column(
        name,
        LargeBinary,
        nullable=not (self.required),
    )


@add_method(BinaryProperty)
def generate_table_information(self, name, is_sdo, table_name):  # noqa: F811
    print("BinaryProperty not handled, yet")
    return None


@add_method(ExtensionsProperty)
def generate_table_information(self, name, is_sdo, table_name):  # noqa: F811
    columns = list()
    columns.append(
        Column(
            "id",
            Text,
            ForeignKey(canonicalize_table_name(table_name), ondelete="CASCADE"),
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
            Text,
            nullable=False,
        ),
    )
    return Table(canonicalize_table_name(table_name + "_" + name), metadata, *columns)


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
def generate_table_information(self, name, is_sdo, table_name):  # noqa: F811
    return ref_column(name, self.specifics)


@add_method(EmbeddedObjectProperty)
def generate_table_information(self, name, is_sdo, table_name):  # noqa: F811
    return generate_object_table(self.type, table_name)


@add_method(ObjectReferenceProperty)
def generate_table_information(self, name, is_sdo, table_name):  # noqa: F811
    raise ValueError(f"Property {name} in {table_name} is of type ObjectReferenceProperty, which is for STIX 2.0 only")


@add_method(ListProperty)
def generate_table_information(self, name, is_sdo, table_name):  # noqa: F811
    if isinstance(self.contained, ReferenceProperty):
        columns = list()
        columns.append(
            Column(
                "id",
                Text,
                ForeignKey(
                    canonicalize_table_name(table_name),
                    ondelete="CASCADE",
                ),
            ),
        )
        columns.append(ref_column("ref_id", self.contained.specifics))
        return Table(canonicalize_table_name(table_name + "_" + name), metadata, *columns)
    elif isinstance(self.contained, EmbeddedObjectProperty):
        columns = list()
        columns.append(
            Column(
                "id",
                Text,
                ForeignKey(
                    canonicalize_table_name(table_name),
                    ondelete="CASCADE",
                ),
            ),
        )
        columns.append(
            Column(
                "ref_id",
                Text,
                nullable=False,
            ),
        )
        CreateTable(Table(canonicalize_table_name(table_name + "_" + name), metadata, *columns))
        return self.contained.generate_table_information(name, False, canonicalize_table_name(table_name + "_" + name))
    else:
        if isinstance(self.contained, Property):
            sql_type = self.contained.determine_sql_type()
            if sql_type:
                return Column(
                    name,
                    ARRAY(sql_type),
                    nullable=not (self.required),
                )


def generate_object_table(stix_object_class, foreign_key_name=None, is_extension=False):
    properties = stix_object_class._properties
    if hasattr(stix_object_class, "_type"):
        table_name = stix_object_class._type
    else:
        table_name = stix_object_class.__name__
    is_sdo = True  # isinstance(stix_object_class, _DomainObject)
    core_properties = SDO_COMMON_PROPERTIES if is_sdo else SCO_COMMON_PROPERTIES
    columns = list()
    tables = list()
    for name, prop in properties.items():
        if name == 'id' or name not in core_properties:
            col = prop.generate_table_information(name, is_sdo, table_name)
            if col is not None and isinstance(col, Column):
                columns.append(col)
            if col is not None and isinstance(col, Table):
                tables.append(col)
    if is_extension:
        columns.append(Column("id", primary_key=True))
    if foreign_key_name:
        columns.append(
            Column(
                "id",
                Text,
                ForeignKey(
                    canonicalize_table_name(foreign_key_name),
                    ondelete="CASCADE",
                ),
            ),
        )
        return Table(canonicalize_table_name(table_name), metadata, *columns)
    else:
        x = Table(canonicalize_table_name(table_name), metadata, *columns)
        print(CreateTable(x))
    for t in tables:
        print(CreateTable(t))
