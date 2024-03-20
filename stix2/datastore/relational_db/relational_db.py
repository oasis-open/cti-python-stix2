from sqlalchemy import MetaData
from sqlalchemy.schema import CreateTable

from stix2.base import _STIXBase
from stix2.datastore import DataSink
from stix2.datastore.relational_db.table_creation import (
    create_core_tables, generate_object_table,
)
from stix2.parsing import parse
from stix2.v21.base import _DomainObject, _Extension, _Observable


def _get_all_subclasses(cls):
    all_subclasses = []

    for subclass in cls.__subclasses__():
        all_subclasses.append(subclass)
        all_subclasses.extend(_get_all_subclasses(subclass))
    return all_subclasses


def insert_object(store, stix_obj, is_sdo):
    pass


def _add(store, stix_data, allow_custom=True, version=None):
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

        insert_object(store, stix_obj, isinstance(stix_obj, _Observable))


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
        self, database_connection, allow_custom=True, version=None,
        instantiate_database=False,
    ):
        super(RelationalDBSink, self).__init__()
        self.allow_custom = allow_custom
        self.metadata = MetaData()
        self.database_connection = database_connection

        if instantiate_database:
            self._instantiate_database()

    def _create_table_objects(self):
        tables = create_core_tables(self.metadata)
        for sdo_class in _get_all_subclasses(_DomainObject):
            new_tables = generate_object_table(sdo_class, self.metadata, True)
            tables.extend(new_tables)
        for sdo_class in _get_all_subclasses(_Observable):
            tables.extend(generate_object_table(sdo_class, self.metadata, False))
        for sdo_class in _get_all_subclasses(_Extension):
            if hasattr(sdo_class, "_applies_to"):
                is_sdo = sdo_class._applies_to == "sdo"
            else:
                is_sdo = False
            tables.extend(generate_object_table(sdo_class, self.metadata, is_sdo, is_extension=True))
        return tables

    def _instantiate_database(self):
        self._create_table_objects()
        self.metadata.create_all(self.database_connection.engine)

    def generate_stix_schema(self):
        tables = self._create_table_objects()
        for t in tables:
            print(CreateTable(t).compile(self.database_connection.engine))

    def add(self, stix_data, version=None):
        _add(self, stix_data, self.allow_custom, version)
    add.__doc__ = _add.__doc__
