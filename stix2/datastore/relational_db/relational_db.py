from sqlalchemy import MetaData, create_engine, select
from sqlalchemy.schema import CreateSchema, CreateTable, Sequence

from stix2.base import _STIXBase
from stix2.datastore import DataSink, DataSource, DataStoreMixin
from stix2.datastore.relational_db.input_creation import (
    generate_insert_for_object,
)
from stix2.datastore.relational_db.table_creation import create_table_objects
from stix2.datastore.relational_db.utils import (
    canonicalize_table_name, schema_for, table_name_for,
)
from stix2.parsing import parse
import stix2.registry
import stix2.utils


def _add(store, stix_data, allow_custom=True, version="2.1"):
    """Add STIX objects to MemoryStore/Sink.

    Adds STIX objects to an in-memory dictionary for fast lookup.
    Recursive function, breaks down STIX Bundles and lists.

    Args:
        store: A MemoryStore, MemorySink or MemorySource object.
        stix_data (list OR dict OR STIX object): STIX objects to be added
        allow_custom (bool): Whether to allow custom properties as well unknown
            custom objects. Note that unknown custom objects cannot be parsed
            into STIX objects, and will be returned as is. Default: False.
        version (str): Which STIX2 version to lock the parser to. (e.g. "2.0",
            "2.1"). If None, the library makes the best effort to figure
            out the spec representation of the object.

    """
    if isinstance(stix_data, list):
        # STIX objects are in a list- recurse on each object
        for stix_obj in stix_data:
            _add(store, stix_obj, allow_custom, version)

    elif stix_data["type"] == "bundle":
        # adding a json bundle - so just grab STIX objects
        for stix_obj in stix_data.get("objects", []):
            _add(store, stix_obj, allow_custom, version)

    else:
        # Adding a single non-bundle object
        if isinstance(stix_data, _STIXBase):
            stix_obj = stix_data
        else:
            stix_obj = parse(stix_data, allow_custom, version)

        store.insert_object(stix_obj)


class RelationalDBStore(DataStoreMixin):
    """Interface to a file directory of STIX objects.

    FileSystemStore is a wrapper around a paired FileSystemSink
    and FileSystemSource.

    Args:
        stix_dir (str): path to directory of STIX objects
        allow_custom (bool): whether to allow custom STIX content to be
            pushed/retrieved. Defaults to True for FileSystemSource side
            (retrieving data) and False for FileSystemSink
            side(pushing data). However, when parameter is supplied, it
            will be applied to both FileSystemSource and FileSystemSink.
        bundlify (bool): whether to wrap objects in bundles when saving
            them. Default: False.
        encoding (str): The encoding to use when reading a file from the
            filesystem.

    Attributes:
        source (FileSystemSource): FileSystemSource
        sink (FileSystemSink): FileSystemSink

    """
    def __init__(self, database_connection_url, allow_custom=None, encoding='utf-8'):
        if allow_custom is None:
            allow_custom_source = True
            allow_custom_sink = False
        else:
            allow_custom_sink = allow_custom_source = allow_custom

        super(RelationalDBStore, self).__init__(
            source=RelationalDBSource(database_connection_url, allow_custom=allow_custom_source, encoding=encoding),
            sink=RelationalDBSink(database_connection_url, allow_custom=allow_custom_sink),
        )


class RelationalDBSink(DataSink):
    """Interface for adding/pushing STIX objects to an in-memory dictionary.

    Designed to be paired with a MemorySource, together as the two
    components of a MemoryStore.

    Args:
        stix_data (dict OR list): valid STIX 2.0 content in
            bundle or a list.
        _store (bool): whether the MemorySink is a part of a MemoryStore,
            in which case "stix_data" is a direct reference to
            shared memory with DataSource. Not user supplied
        allow_custom (bool): whether to allow custom objects/properties
            when exporting STIX content to file.
            Default: True.
        version (str): If present, it forces the parser to use the version
            provided. Otherwise, the library will make the best effort based
            on checking the "spec_version" property.

    Attributes:
        _data (dict): the in-memory dict that holds STIX objects.
            If part of a MemoryStore, the dict is shared with a MemorySource

    """
    def __init__(
        self, database_connection_url, allow_custom=True, version=None,
        instantiate_database=True, *stix_object_classes
    ):
        super(RelationalDBSink, self).__init__()
        self.allow_custom = allow_custom
        self.metadata = MetaData()
        self.database_connection = create_engine(database_connection_url)

        self.tables = create_table_objects(
            self.metadata, stix_object_classes
        )
        self.tables_dictionary = dict()
        for t in self.tables:
            self.tables_dictionary[canonicalize_table_name(t.name, t.schema)] = t

        if instantiate_database:
            self._create_schemas()
            self._instantiate_database()

    def _create_schemas(self):
        with self.database_connection.begin() as trans:
            trans.execute(CreateSchema("common", if_not_exists=True))
            trans.execute(CreateSchema("sdo", if_not_exists=True))
            trans.execute(CreateSchema("sco", if_not_exists=True))
            trans.execute(CreateSchema("sro", if_not_exists=True))

    def _instantiate_database(self):
        self.sequence = Sequence("my_general_seq", metadata=self.metadata, start=1)
        self.metadata.create_all(self.database_connection)

    def generate_stix_schema(self):
        for t in self.tables:
            print(CreateTable(t).compile(self.database_connection))
            print()

    def add(self, stix_data, version=None):
        _add(self, stix_data)
    add.__doc__ = _add.__doc__

    def insert_object(self, stix_object):
        schema_name = "sdo" if "created" in stix_object else "sco"
        with self.database_connection.begin() as trans:
            statements = generate_insert_for_object(self, stix_object, schema_name)
            for stmt in statements:
                print("executing: ", stmt)
                trans.execute(stmt)
            trans.commit()


class RelationalDBSource(DataSource):

    def __init__(
        self, database_connection_url, *stix_object_classes
    ):
        self.metadata = MetaData()
        self.database_connection = create_engine(database_connection_url)
        create_table_objects(
            self.metadata, stix_object_classes
        )

    def get(self, stix_id, version=None, _composite_filters=None):

        stix_type = stix2.utils.get_type_from_id(stix_id)
        stix_class = stix2.registry.class_for_type(
            # TODO: give user control over STIX version used?
            stix_type, stix_version=stix2.DEFAULT_VERSION
        )

        # Info about the type-specific table
        type_table_name = table_name_for(stix_type)
        type_schema_name = schema_for(stix_class)
        type_table = self.metadata.tables[f"{type_schema_name}.{type_table_name}"]

        # Some fixed info about core tables
        if type_schema_name == "sco":
            core_table_name = "common.core_sco"
        else:
            # for SROs and SMOs too?
            core_table_name = "common.core_sdo"

        core_table = self.metadata.tables[core_table_name]

        # Both core and type-specific tables have "id"; let's not duplicate
        # that in the result set columns.  Is there a better way to do this?
        type_cols_except_id = (
            col for col in type_table.c if col.key != "id"
        )

        core_type_select = select(core_table, *type_cols_except_id) \
            .join(type_table) \
            .where(core_table.c.id == stix_id)

        obj_dict = {}
        with self.database_connection.begin() as conn:
            # Should be at most one matching row
            sco_data = conn.execute(core_type_select).mappings().first()
            obj_dict.update(sco_data)

        return stix_class(**obj_dict)

    def all_versions(self, stix_id, version=None, _composite_filters=None):
        pass

    def query(self, query=None):
        pass

    def generate_stix_schema(self):
        for t in self.metadata.tables.values():
            print(CreateTable(t).compile(self.database_connection.engine))
