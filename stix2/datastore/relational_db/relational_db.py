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
    def __init__(
        self, database_connection_url, allow_custom=True, version=None,
        instantiate_database=True, *stix_object_classes
    ):
        """
        Initialize this store.

        Args:
            database_connection_url: An SQLAlchemy URL referring to a database
            allow_custom: Whether custom content is allowed when processing
                dict content to be added to the store
            version: TODO: unused so far
            instantiate_database: Whether tables, etc should be created in the
                database (only necessary the first time)
            *stix_object_classes: STIX object classes to map into table schemas
                (and ultimately database tables, if instantiation is desired).
                This can be used to limit which table schemas are created, if
                one is only working with a subset of STIX types.  If not given,
                auto-detect all classes and create table schemas for all of
                them.
        """
        database_connection = create_engine(database_connection_url)

        self.metadata = MetaData()
        create_table_objects(
            self.metadata, stix_object_classes
        )

        super().__init__(
            source=RelationalDBSource(
                database_connection,
                metadata=self.metadata
            ),
            sink=RelationalDBSink(
                database_connection,
                allow_custom=allow_custom,
                version=version,
                instantiate_database=instantiate_database,
                metadata=self.metadata
            ),
        )


class RelationalDBSink(DataSink):
    def __init__(
        self, database_connection_or_url, allow_custom=True, version=None,
        instantiate_database=True, *stix_object_classes, metadata=None
    ):
        """
        Initialize this sink.  Only one of stix_object_classes and metadata
        should be given: if the latter is given, assume table schemas are
        already created.

        Args:
            database_connection_or_url: An SQLAlchemy engine object, or URL
            allow_custom: Whether custom content is allowed when processing
                dict content to be added to the sink
            version: TODO: unused so far
            instantiate_database: Whether tables, etc should be created in the
                database (only necessary the first time)
            *stix_object_classes: STIX object classes to map into table schemas
                (and ultimately database tables, if instantiation is desired).
                This can be used to limit which table schemas are created, if
                one is only working with a subset of STIX types.  If not given,
                auto-detect all classes and create table schemas for all of
                them.  If metadata is given, the table data therein is used and
                this argument is ignored.
            metadata: SQLAlchemy MetaData object containing table information.
                Only applicable when this class is instantiated via a store,
                so that table information can be constructed once and shared
                between source and sink.
        """
        super(RelationalDBSink, self).__init__()

        if isinstance(database_connection_or_url, str):
            self.database_connection = create_engine(database_connection_or_url)
        else:
            self.database_connection = database_connection_or_url

        if metadata:
            self.metadata = metadata
        else:
            self.metadata = MetaData()
            create_table_objects(
                self.metadata, stix_object_classes
            )

        self.allow_custom = allow_custom

        self.tables_dictionary = dict()
        for t in self.metadata.tables.values():
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
        for t in self.metadata.tables.values():
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
        self, database_connection_or_url, *stix_object_classes, metadata=None
    ):
        """
        Initialize this source.  Only one of stix_object_classes and metadata
        should be given: if the latter is given, assume table schemas are
        already created.  Instances of this class do not create the actual
        database tables; see the source/sink for that.

        Args:
            database_connection_or_url: An SQLAlchemy engine object, or URL
            *stix_object_classes: STIX object classes to map into table schemas.
                This can be used to limit which schemas are created, if one is
                only working with a subset of STIX types.  If not given,
                auto-detect all classes and create schemas for all of them.
                If metadata is given, the table data therein is used and this
                argument is ignored.
            metadata: SQLAlchemy MetaData object containing table information.
                Only applicable when this class is instantiated via a store,
                so that table information can be constructed once and shared
                between source and sink.
        """
        super().__init__()

        if isinstance(database_connection_or_url, str):
            self.database_connection = create_engine(database_connection_or_url)
        else:
            self.database_connection = database_connection_or_url

        if metadata:
            self.metadata = metadata
        else:
            self.metadata = MetaData()
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

        return stix_class(**obj_dict, allow_custom=True)

    def all_versions(self, stix_id, version=None, _composite_filters=None):
        pass

    def query(self, query=None):
        pass
