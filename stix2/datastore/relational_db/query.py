import inspect

import sqlalchemy as sa

import stix2
from stix2.datastore import DataSourceError
from stix2.datastore.relational_db.utils import (
    canonicalize_table_name, schema_for, table_name_for,
)
import stix2.properties
import stix2.utils


def _check_support(stix_id):
    """
    Misc support checks for the relational data source.  May be better to error
    out up front and say a type is not supported, than die with some cryptic
    SQLAlchemy or other error later.  This runs for side-effects (raises
    an exception) and doesn't return anything.

    :param stix_id: A STIX ID.  The basis for reading an object, used to
        determine support
    """
    # language-content has a complicated structure in its "contents"
    # property, which is not currently supported for storage in a
    # relational database.
    stix_type = stix2.utils.get_type_from_id(stix_id)
    if stix_type in ("language-content",):
        raise DataSourceError(f"Reading {stix_type} objects is not supported.")


def _tables_for(stix_class, metadata):
    """
    Get the core and type-specific tables for the given class

    :param stix_class: A class for a STIX object type
    :param metadata: SQLAlchemy Metadata object containing all the table
        information
    :return: A (core_table, type_table) 2-tuple as SQLAlchemy Table objects
    """
    # Info about the type-specific table
    type_table_name = table_name_for(stix_class)
    type_schema_name = schema_for(stix_class)
    type_table = metadata.tables[f"{type_schema_name}.{type_table_name}"]

    # Some fixed info about core tables
    if type_schema_name == "sco":
        core_table_name = "common.core_sco"
    else:
        # for SROs and SMOs too?
        core_table_name = "common.core_sdo"

    core_table = metadata.tables[core_table_name]

    return core_table, type_table


def _stix2_class_for(stix_id):
    """
    Find the class for the STIX type indicated by the given STIX ID.

    :param stix_id: A STIX ID
    """
    stix_type = stix2.utils.get_type_from_id(stix_id)
    stix_class = stix2.registry.class_for_type(
        # TODO: give user control over STIX version used?
        stix_type, stix_version=stix2.DEFAULT_VERSION,
    )

    return stix_class


def _read_simple_properties(stix_id, core_table, type_table, conn):
    """
    Read "simple" property values, i.e. those which don't need tables other
    than the core/type-specific tables: they're stored directly in columns of
    those tables.  These two tables are joined and must have a defined foreign
    key constraint between them.

    :param stix_id: A STIX ID
    :param core_table: A core table
    :param type_table: A type-specific table
    :param conn: An SQLAlchemy DB connection
    :return: A mapping containing the properties and values read
    """
    # Both core and type-specific tables have "id"; let's not duplicate that
    # in the result set columns.  Is there a better way to do this?
    type_cols_except_id = (
        col for col in type_table.c if col.key != "id"
    )

    core_type_select = sa.select(core_table, *type_cols_except_id) \
        .join(type_table) \
        .where(core_table.c.id == stix_id)

    # Should be at most one matching row
    obj_dict = conn.execute(core_type_select).mappings().first()

    return obj_dict


def _read_simple_array(fk_id, elt_column_name, array_table, conn):
    """
    Read array elements from a given table.

    :param fk_id: A foreign key value used to find the correct array elements
    :param elt_column_name: The name of the table column which contains the
        array elements
    :param array_table: A SQLAlchemy Table object containing the array data
    :param conn: An SQLAlchemy DB connection
    :return: The array, as a list
    """
    stmt = sa.select(array_table.c[elt_column_name]).where(array_table.c.id == fk_id)
    refs = conn.scalars(stmt).all()
    return refs


def _read_hashes(fk_id, hashes_table, conn):
    """
    Read hashes from a table.

    :param fk_id: A foreign key value used to filter table rows
    :param hashes_table: An SQLAlchemy Table object
    :param conn: An SQLAlchemy DB connection
    :return: The hashes as a dict, or None if no hashes were found
    """
    stmt = sa.select(hashes_table.c.hash_name, hashes_table.c.hash_value).where(
        hashes_table.c.id == fk_id,
    )

    results = conn.execute(stmt)
    hashes = dict(results.all()) or None
    return hashes


def _read_external_references(stix_id, metadata, conn):
    """
    Read external references from some fixed tables in the common schema.

    :param stix_id: A STIX ID used to filter table rows
    :param metadata: SQLAlchemy Metadata object containing all the table
        information
    :param conn: An SQLAlchemy DB connection
    :return: The external references, as a list of dicts
    """
    ext_refs_table = metadata.tables["common.external_references"]
    ext_refs_hashes_table = metadata.tables["common.external_references_hashes"]
    ext_refs = []

    ext_refs_columns = (col for col in ext_refs_table.c if col.key != "id")
    stmt = sa.select(*ext_refs_columns).where(ext_refs_table.c.id == stix_id)
    ext_refs_results = conn.execute(stmt)
    for ext_ref_mapping in ext_refs_results.mappings():
        # make a dict; we will need to modify this mapping
        ext_ref_dict = dict(ext_ref_mapping)
        hash_ref_id = ext_ref_dict.pop("hash_ref_id")

        hashes_dict = _read_hashes(hash_ref_id, ext_refs_hashes_table, conn)
        if hashes_dict:
            ext_ref_dict["hashes"] = hashes_dict

        ext_refs.append(ext_ref_dict)

    return ext_refs


def _read_object_marking_refs(stix_id, stix_type_class, metadata, conn):
    """
    Read object marking refs from one of a couple special tables in the common
    schema.

    :param stix_id: A STIX ID, used to filter table rows
    :param stix_type_class: STIXTypeClass enum value, used to determine whether
        to read the table for SDOs or SCOs
    :param metadata: SQLAlchemy Metadata object containing all the table
        information
    :param conn: An SQLAlchemy DB connection
    :return: The references as a list of strings
    """

    marking_table_name = "object_marking_refs_"
    if stix_type_class is stix2.utils.STIXTypeClass.SCO:
        marking_table_name += "sco"
    else:
        marking_table_name += "sdo"

    # The SCO/SDO object_marking_refs tables are mostly identical; they just
    # have different foreign key constraints (to different core tables).
    marking_table = metadata.tables["common." + marking_table_name]

    stmt = sa.select(marking_table.c.ref_id).where(marking_table.c.id == stix_id)
    refs = conn.scalars(stmt).all()

    return refs


def _read_granular_markings(stix_id, stix_type_class, metadata, conn, db_backend):
    """
    Read granular markings from one of a couple special tables in the common
    schema.

    :param stix_id: A STIX ID, used to filter table rows
    :param stix_type_class: STIXTypeClass enum value, used to determine whether
        to read the table for SDOs or SCOs
    :param metadata: SQLAlchemy Metadata object containing all the table
        information
    :param conn: An SQLAlchemy DB connection
    :param db_backend: A backend object with information about how data is
        stored in the database
    :return: Granular markings as a list of dicts
    """

    marking_table_name = "granular_marking_"
    if stix_type_class is stix2.utils.STIXTypeClass.SCO:
        marking_table_name += "sco"
    else:
        marking_table_name += "sdo"

    marking_table = metadata.tables["common." + marking_table_name]

    if db_backend.array_allowed():
        # arrays allowed: everything combined in the same table
        stmt = sa.select(
            marking_table.c.lang,
            marking_table.c.marking_ref,
            marking_table.c.selectors,
        ).where(marking_table.c.id == stix_id)

        marking_dicts = conn.execute(stmt).mappings().all()

    else:
        # arrays not allowed: selectors are in their own table
        stmt = sa.select(
            marking_table.c.lang,
            marking_table.c.marking_ref,
            marking_table.c.selectors,
        ).where(marking_table.c.id == stix_id)

        marking_dicts = list(conn.execute(stmt).mappings())

        for idx, marking_dict in enumerate(marking_dicts):
            # make a mutable shallow-copy of the row mapping
            marking_dicts[idx] = marking_dict = dict(marking_dict)
            selector_id = marking_dict.pop("selectors")

            selector_table_name = f"{marking_table.fullname}_selector"
            selector_table = metadata.tables[selector_table_name]

            selectors = _read_simple_array(
                selector_id,
                "selector",
                selector_table,
                conn
            )
            marking_dict["selectors"] = selectors

    return marking_dicts


def _read_kill_chain_phases(stix_id, type_table, metadata, conn):
    """
    Read kill chain phases from a table.

    :param stix_id: A STIX ID used to filter table rows
    :param type_table: A "parent" table whose name is used to compute the
        kill chain phases table name
    :param metadata: SQLAlchemy Metadata object containing all the table
        information
    :param conn: An SQLAlchemy DB connection
    :return: Kill chain phases as a list of dicts
    """

    kill_chain_phases_table = metadata.tables[type_table.fullname + "_kill_chain_phase"]
    stmt = sa.select(
        kill_chain_phases_table.c.kill_chain_name,
        kill_chain_phases_table.c.phase_name,
    ).where(kill_chain_phases_table.c.id == stix_id)

    kill_chain_phases = conn.execute(stmt).mappings().all()
    return kill_chain_phases


def _read_dictionary_property(stix_id, type_table, prop_name, prop_instance, metadata, conn):
    """
    Read a dictionary from a table.

    :param stix_id: A STIX ID, used to filter table rows
    :param type_table: A "parent" table whose name is used to compute the name
        of the dictionary table
    :param prop_name: The dictionary property name
    :param prop_instance: The dictionary property instance
    :param metadata: SQLAlchemy Metadata object containing all the table
        information
    :param conn: An SQLAlchemy DB connection
    :return: The dictionary, or None if no dictionary entries were found
    """
    dict_table_name = f"{type_table.fullname}_{prop_name}"
    dict_table = metadata.tables[dict_table_name]

    if len(prop_instance.valid_types) == 1:
        stmt = sa.select(
            dict_table.c.name, dict_table.c.value,
        ).where(
            dict_table.c.id == stix_id,
        )

        results = conn.execute(stmt)
        dict_value = dict(results.all())

    else:
        # In this case, we get one column per valid type
        type_cols = (col for col in dict_table.c if col.key not in ("id", "name"))
        stmt = sa.select(dict_table.c.name, *type_cols).where(dict_table.c.id == stix_id)
        results = conn.execute(stmt)

        dict_value = {}
        for row in results:
            key, *type_values = row
            # Exactly one of the type columns should be non-None; get that one
            non_null_values = (v for v in type_values if v is not None)
            first_non_null_value = next(non_null_values, None)
            if first_non_null_value is None:
                raise DataSourceError(
                    f'In dictionary table {dict_table.fullname}, key "{key}"'
                    " did not map to a non-null value",
                )

            dict_value[key] = first_non_null_value

    # DictionaryProperty doesn't like empty dicts.
    dict_value = dict_value or None

    return dict_value


def _read_embedded_object(obj_id, parent_table, embedded_type, metadata, conn):
    """
    Read an embedded object from the database.

    :param obj_id: An ID value used to identify a particular embedded object,
        used to filter table rows
    :param parent_table: A "parent" table whose name is used to compute the
        name of the embedded object table
    :param embedded_type: The Python class used to represent the embedded
        type (a _STIXBase subclass)
    :param metadata: SQLAlchemy Metadata object containing all the table
        information
    :param conn: An SQLAlchemy DB connection
    :return: An instance of embedded_type
    """

    embedded_table_name = canonicalize_table_name(
        f"{parent_table.name}_{embedded_type.__name__}",
        parent_table.schema,
    )
    embedded_table = metadata.tables[embedded_table_name]

    # The PK column in this case is a bookkeeping column and does not
    # correspond to an actual embedded object property.  So don't select
    # that one.
    non_id_cols = (col for col in embedded_table.c if col.key != "id")

    stmt = sa.select(*non_id_cols).where(embedded_table.c.id == obj_id)
    mapping_row = conn.execute(stmt).mappings().first()

    if mapping_row is None:
        obj = None

    else:
        obj_dict = dict(mapping_row)

        for prop_name, prop_instance in embedded_type._properties.items():
            if prop_name not in obj_dict:
                prop_value = _read_complex_property_value(
                    obj_id,
                    prop_name,
                    prop_instance,
                    embedded_table,
                    metadata,
                    conn,
                )

                if prop_value is not None:
                    obj_dict[prop_name] = prop_value

        obj = embedded_type(**obj_dict, allow_custom=True)

    return obj


def _read_embedded_object_list(fk_id, join_table, embedded_type, metadata, conn):
    """
    Read a list of embedded objects from database tables.

    :param fk_id: A foreign key ID used to filter rows from the join table,
        which acts to find relevant embedded objects
    :param join_table: An SQLAlchemy Table object which is the required join
        table
    :param embedded_type: The Python class used to represent the list element
        embedded type (a _STIXBase subclass)
    :param metadata: SQLAlchemy Metadata object containing all the table
        information
    :param conn: An SQLAlchemy DB connection
    :return: A list of instances of embedded_type
    """

    embedded_table_name = canonicalize_table_name(
        f"{join_table.name}_{embedded_type.__name__}",
        join_table.schema,
    )
    embedded_table = metadata.tables[embedded_table_name]

    stmt = sa.select(embedded_table).join(join_table).where(join_table.c.id == fk_id)
    results = conn.execute(stmt)
    obj_list = []
    for result_mapping in results.mappings():
        obj_dict = dict(result_mapping)
        obj_id = obj_dict.pop("id")

        for prop_name, prop_instance in embedded_type._properties.items():
            if prop_name not in obj_dict:
                prop_value = _read_complex_property_value(
                    obj_id,
                    prop_name,
                    prop_instance,
                    embedded_table,
                    metadata,
                    conn,
                )

                if prop_value is not None:
                    obj_dict[prop_name] = prop_value

        obj = embedded_type(**obj_dict, allow_custom=True)
        obj_list.append(obj)

    return obj_list


def _read_complex_property_value(obj_id, prop_name, prop_instance, obj_table, metadata, conn):
    """
    Read property values which require auxiliary tables to store.  These are
    idiosyncratic and just require a lot of special cases.  This function has
    no special support for top-level common properties, so it is more
    general-purpose, suitable for any sort of object (top level or embedded).

    :param obj_id: An ID of the owning object.  Would be a STIX ID for a
        top-level object, but could also be something else for sub-objects.
        Used as a foreign key value in queries, so we only get values for this
        object.
    :param prop_name: The name of the property to read
    :param prop_instance: A Property (subclass) instance with property
        config information
    :param obj_table: The table for the owning object.  Mainly used for its
        name; auxiliary table names are based on this
    :param metadata: SQLAlchemy Metadata object containing all the table
        information
    :param conn: An SQLAlchemy DB connection
    :return: The property value
    """

    prop_value = None

    if isinstance(prop_instance, stix2.properties.ListProperty):

        if isinstance(prop_instance.contained, stix2.properties.ReferenceProperty):
            ref_table_name = f"{obj_table.fullname}_{prop_name}"
            ref_table = metadata.tables[ref_table_name]
            prop_value = _read_simple_array(obj_id, "ref_id", ref_table, conn)

        elif isinstance(prop_instance.contained, (
            # Most of these list-of-simple-type cases would occur when array
            # columns are disabled.
            stix2.properties.BinaryProperty,
            stix2.properties.BooleanProperty,
            stix2.properties.EnumProperty,
            stix2.properties.HexProperty,
            stix2.properties.IntegerProperty,
            stix2.properties.FloatProperty,
            stix2.properties.StringProperty,
            stix2.properties.TimestampProperty,
        )):
            array_table_name = f"{obj_table.fullname}_{prop_name}"
            array_table = metadata.tables[array_table_name]
            prop_value = _read_simple_array(
                obj_id,
                prop_name,
                array_table,
                conn
            )

        elif isinstance(prop_instance.contained, stix2.properties.EmbeddedObjectProperty):
            join_table_name = f"{obj_table.fullname}_{prop_name}"
            join_table = metadata.tables[join_table_name]
            prop_value = _read_embedded_object_list(
                obj_id,
                join_table,
                prop_instance.contained.type,
                metadata,
                conn,
            )

        elif inspect.isclass(prop_instance.contained) and issubclass(prop_instance.contained, stix2.KillChainPhase):
            prop_value = _read_kill_chain_phases(obj_id, obj_table, metadata, conn)

        else:
            raise DataSourceError(
                f'Not implemented: read "{prop_name}" property value'
                f" of type list-of {prop_instance.contained}",
            )

    elif isinstance(prop_instance, stix2.properties.HashesProperty):
        hashes_table_name = f"{obj_table.fullname}_{prop_name}"
        hashes_table = metadata.tables[hashes_table_name]
        prop_value = _read_hashes(obj_id, hashes_table, conn)

    elif isinstance(prop_instance, stix2.properties.ExtensionsProperty):
        # TODO: add support for extensions
        pass

    elif isinstance(prop_instance, stix2.properties.DictionaryProperty):
        # ExtensionsProperty/HashesProperty subclasses DictionaryProperty, so
        # this must come after those
        prop_value = _read_dictionary_property(obj_id, obj_table, prop_name, prop_instance, metadata, conn)

    elif isinstance(prop_instance, stix2.properties.EmbeddedObjectProperty):
        prop_value = _read_embedded_object(
            obj_id,
            obj_table,
            prop_instance.type,
            metadata,
            conn,
        )

    else:
        raise DataSourceError(
            f'Not implemented: read "{prop_name}" property value'
            f" of type {prop_instance.__class__}",
        )

    return prop_value


def _read_complex_top_level_property_value(
    stix_id,
    stix_type_class,
    prop_name,
    prop_instance,
    type_table,
    metadata,
    conn,
    db_backend
):
    """
    Read property values which require auxiliary tables to store.  These
    require a lot of special cases.  This function has additional support for
    reading top-level common properties, which use special fixed tables.

    :param stix_id: STIX ID of an object to read
    :param stix_type_class: The kind of object (SCO, SDO, etc).  Which DB
        tables to read can depend on this.
    :param prop_name: The name of the property to read
    :param prop_instance: A Property (subclass) instance with property
        config information
    :param type_table: The non-core base table used for this STIX type.  Mainly
        used for its name; auxiliary table names are based on this
    :param metadata: SQLAlchemy Metadata object containing all the table
        information
    :param conn: An SQLAlchemy DB connection
    :param db_backend: A backend object with information about how data is
        stored in the database
    :return: The property value
    """

    # Common properties: these use a fixed set of tables for all STIX objects
    if prop_name == "external_references":
        prop_value = _read_external_references(stix_id, metadata, conn)

    elif prop_name == "object_marking_refs":
        prop_value = _read_object_marking_refs(
            stix_id,
            stix_type_class,
            metadata,
            conn
        )

    elif prop_name == "granular_markings":
        prop_value = _read_granular_markings(
            stix_id,
            stix_type_class,
            metadata,
            conn,
            db_backend
        )

    # Will apply when array columns are unsupported/disallowed by the backend
    elif prop_name == "labels":
        label_table = metadata.tables[
            f"common.core_{stix_type_class.name.lower()}_labels"
        ]
        prop_value = _read_simple_array(stix_id, "label", label_table, conn)

    else:
        # Other properties use specific table patterns depending on property type
        prop_value = _read_complex_property_value(
            stix_id,
            prop_name,
            prop_instance,
            type_table,
            metadata,
            conn
        )

    return prop_value


def read_object(stix_id, metadata, conn, db_backend):
    """
    Read a STIX object from the database, identified by a STIX ID.

    :param stix_id: A STIX ID
    :param metadata: SQLAlchemy Metadata object containing all the table
        information
    :param conn: An SQLAlchemy DB connection
    :param db_backend: A backend object with information about how data is
        stored in the database
    :return: A STIX object
    """
    _check_support(stix_id)

    stix_class = _stix2_class_for(stix_id)

    if not stix_class:
        stix_type = stix2.utils.get_type_from_id(stix_id)
        raise DataSourceError("Can't find registered class for type: " + stix_type)

    core_table, type_table = _tables_for(stix_class, metadata)

    if type_table.schema == "common":
        # Applies to extension-definition SMO, whose data is stored in the
        # common schema; it does not get its own.  This type class is used to
        # determine which common tables to use; its markings are
        # in the *_sdo tables.
        stix_type_class = stix2.utils.STIXTypeClass.SDO
    else:
        stix_type_class = stix2.utils.to_enum(type_table.schema, stix2.utils.STIXTypeClass)

    simple_props = _read_simple_properties(stix_id, core_table, type_table, conn)
    if simple_props is None:
        # could not find anything for the given ID!
        return None

    obj_dict = dict(simple_props)
    obj_dict["type"] = stix_class._type

    for prop_name, prop_instance in stix_class._properties.items():
        if prop_name not in obj_dict:
            prop_value = _read_complex_top_level_property_value(
                stix_id,
                stix_type_class,
                prop_name,
                prop_instance,
                type_table,
                metadata,
                conn,
                db_backend
            )

            if prop_value is not None:
                obj_dict[prop_name] = prop_value

    stix_obj = stix_class(**obj_dict, allow_custom=True)
    return stix_obj