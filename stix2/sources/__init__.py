"""Python STIX 2.0 Sources

.. autosummary::
   :toctree: sources

   filesystem
   filters
   memory
   taxii

|
"""

from abc import ABCMeta, abstractmethod
import uuid

from six import with_metaclass

from stix2.utils import deduplicate


def make_id():
    return str(uuid.uuid4())


class DataStore(object):
    """An implementer can subclass to create custom behavior from
    this class for the specific DataStores.

    Args:
        source (DataSource): An existing DataSource to use
             as this DataStore's DataSource component
        sink (DataSink): An existing DataSink to use
             as this DataStore's DataSink component

    Attributes:
        id (str): A unique UUIDv4 to identify this DataStore.
        source (DataSource): An object that implements DataSource class.
        sink (DataSink): An object that implements DataSink class.

    """
    def __init__(self, source=None, sink=None):
        super(DataStore, self).__init__()
        self.id = make_id()
        self.source = source
        self.sink = sink

    def get(self, *args, **kwargs):
        """Retrieve the most recent version of a single STIX object by ID.

        Translate get() call to the appropriate DataSource call.

        Args:
            stix_id (str): the id of the STIX object to retrieve.

        Returns:
            stix_obj: the single most recent version of the STIX
                object specified by the "id".

        """
        return self.source.get(*args, **kwargs)

    def all_versions(self, *args, **kwargs):
        """Retrieve all versions of a single STIX object by ID.

        Translate all_versions() call to the appropriate DataSource call.

        Args:
            stix_id (str): the id of the STIX object to retrieve.

        Returns:
            stix_objs (list): a list of STIX objects

        """
        return self.source.all_versions(*args, **kwargs)

    def query(self, *args, **kwargs):
        """Retrieve STIX objects matching a set of filters.

        Translate query() call to the appropriate DataSource call.

        Args:
            query (list): a list of filters (which collectively are the query)
                to conduct search on.

        Returns:
            stix_objs (list): a list of STIX objects

        """
        return self.source.query(*args, **kwargs)

    def add(self, *args, **kwargs):
        """Method for storing STIX objects.

        Define custom behavior before storing STIX objects using the associated
        DataSink. Translates add() to the appropriate DataSink call.

        Args:
            stix_objs (list): a list of STIX objects

        """
        return self.sink.add(*args, **kwargs)


class DataSink(with_metaclass(ABCMeta)):
    """An implementer will create a concrete subclass from
    this class for the specific DataSink.

    Attributes:
        id (str): A unique UUIDv4 to identify this DataSink.

    """
    def __init__(self):
        super(DataSink, self).__init__()
        self.id = make_id()

    @abstractmethod
    def add(self, stix_objs):
        """Method for storing STIX objects.

        Implement: Specific data sink API calls, processing,
        functionality required for adding data to the sink

        Args:
            stix_objs (list): a list of STIX objects (where each object is a
                STIX object)

        """


class DataSource(with_metaclass(ABCMeta)):
    """An implementer will create a concrete subclass from
    this class for the specific DataSource.

    Attributes:
        id (str): A unique UUIDv4 to identify this DataSource.
        filters (set): A collection of filters attached to this DataSource.

    """
    def __init__(self):
        super(DataSource, self).__init__()
        self.id = make_id()
        self.filters = set()

    @abstractmethod
    def get(self, stix_id):
        """
        Implement: Specific data source API calls, processing,
        functionality required for retrieving data from the data source

        Args:
            stix_id (str): the id of the STIX 2.0 object to retrieve. Should
                return a single object, the most recent version of the object
                specified by the "id".

        Returns:
            stix_obj: the STIX object

        """

    @abstractmethod
    def all_versions(self, stix_id):
        """
        Implement: Similar to get() except returns list of all object versions
        of the specified "id". In addition, implement the specific data
        source API calls, processing, functionality required for retrieving
        data from the data source.

        Args:
            stix_id (str): The id of the STIX 2.0 object to retrieve. Should
                return a list of objects, all the versions of the object
                specified by the "id".

        Returns:
            stix_objs (list): a list of STIX objects

        """

    @abstractmethod
    def query(self, query=None):
        """
        Implement: The specific data source API calls, processing,
        functionality required for retrieving query from the data source

        Args:
            query (list): a list of filters (which collectively are the query)
                to conduct search on.

        Returns:
            stix_objs (list): a list of STIX objects

        """


class CompositeDataSource(DataSource):
    """Controller for all the attached DataSources.

    A user can have a single CompositeDataSource as an interface
    the a set of DataSources. When an API call is made to the
    CompositeDataSource, it is delegated to each of the (real)
    DataSources that are attached to it.

    DataSources can be attached to CompositeDataSource for a variety
    of reasons, e.g. common filters, organization, less API calls.

    Attributes:

        data_sources (list): A dictionary of DataSource objects; to be
            controlled and used by the Data Source Controller object.

    """
    def __init__(self):
        """Create a new STIX Data Source.

        Args:

        """
        super(CompositeDataSource, self).__init__()
        self.data_sources = []

    def get(self, stix_id, _composite_filters=None):
        """Retrieve STIX object by STIX ID

        Federated retrieve method, iterates through all DataSources
        defined in the "data_sources" parameter. Each data source has a
        specific API retrieve-like function and associated parameters. This
        function does a federated retrieval and consolidation of the data
        returned from all the STIX data sources.

        A composite data source will pass its attached filters to
        each configured data source, pushing filtering to them to handle.

        Args:
            stix_id (str): the id of the STIX object to retrieve.
            _composite_filters (list): a list of filters passed from a
                CompositeDataSource (i.e. if this CompositeDataSource is attached
                to another parent CompositeDataSource), not user supplied.

        Returns:
            stix_obj: the STIX object to be returned.

        """
        if not self.has_data_sources():
            raise AttributeError('CompositeDataSource has no data sources')

        all_data = []
        all_filters = set()
        all_filters.update(self.filters)

        if _composite_filters:
            all_filters.update(_composite_filters)

        # for every configured Data Source, call its retrieve handler
        for ds in self.data_sources:
            data = ds.get(stix_id=stix_id, _composite_filters=all_filters)
            if data:
                all_data.append(data)

        # remove duplicate versions
        if len(all_data) > 0:
            all_data = deduplicate(all_data)
        else:
            return None

        # reduce to most recent version
        stix_obj = sorted(all_data, key=lambda k: k['modified'], reverse=True)[0]

        return stix_obj

    def all_versions(self, stix_id, _composite_filters=None):
        """Retrieve all versions of a STIX object by STIX ID.

        Federated all_versions retrieve method - iterates through all
        DataSources defined in "data_sources".

        A composite data source will pass its attached filters to
        each configured data source, pushing filtering to them to handle.

        Args:
            stix_id (str): id of the STIX objects to retrieve.
            _composite_filters (list): a list of filters passed from a
                CompositeDataSource (i.e. if this CompositeDataSource is
                attached to a parent CompositeDataSource), not user supplied.

        Returns:
            all_data (list): list of STIX objects that have the specified id

        """
        if not self.has_data_sources():
            raise AttributeError('CompositeDataSource has no data sources')

        all_data = []
        all_filters = set()

        all_filters.update(self.filters)

        if _composite_filters:
            all_filters.update(_composite_filters)

        # retrieve STIX objects from all configured data sources
        for ds in self.data_sources:
            data = ds.all_versions(stix_id=stix_id, _composite_filters=all_filters)
            all_data.extend(data)

        # remove exact duplicates (where duplicates are STIX 2.0 objects
        # with the same 'id' and 'modified' values)
        if len(all_data) > 0:
            all_data = deduplicate(all_data)

        return all_data

    def query(self, query=None, _composite_filters=None):
        """Retrieve STIX objects that match a query.

        Federate the query to all DataSources attached to the
        Composite Data Source.

        Args:
            query (list): list of filters to search on.
            _composite_filters (list): a list of filters passed from a
                CompositeDataSource (i.e. if this CompositeDataSource is
                attached to a parent CompositeDataSource), not user supplied.

        Returns:
            all_data (list): list of STIX objects to be returned

        """
        if not self.has_data_sources():
            raise AttributeError('CompositeDataSource has no data sources')

        if not query:
            # don't mess with the query (i.e. convert to a set, as that's done
            # within the specific DataSources that are called)
            query = []

        all_data = []

        all_filters = set()
        all_filters.update(self.filters)

        if _composite_filters:
            all_filters.update(_composite_filters)

        # federate query to all attached data sources,
        # pass composite filters to id
        for ds in self.data_sources:
            data = ds.query(query=query, _composite_filters=all_filters)
            all_data.extend(data)

        # remove exact duplicates (where duplicates are STIX 2.0
        # objects with the same 'id' and 'modified' values)
        if len(all_data) > 0:
            all_data = deduplicate(all_data)

        return all_data

    def add_data_source(self, data_source):
        """Attach a DataSource to CompositeDataSource instance

        Args:
            data_source (DataSource): a stix2.DataSource to attach
                to the CompositeDataSource

        """
        if issubclass(data_source.__class__, DataSource):
            if data_source.id not in [ds_.id for ds_ in self.data_sources]:
                # check DataSource not already attached CompositeDataSource
                self.data_sources.append(data_source)
        else:
            raise TypeError("DataSource (to be added) is not of type stix2.DataSource. DataSource type is '%s'" % type(data_source))

        return

    def add_data_sources(self, data_sources):
        """Attach list of DataSources to CompositeDataSource instance

        Args:
            data_sources (list): stix2.DataSources to attach to
                CompositeDataSource
        """
        for ds in data_sources:
            self.add_data_source(ds)
        return

    def remove_data_source(self, data_source_id):
        """Remove DataSource from the CompositeDataSource instance

        Args:
            data_source_id (str): DataSource IDs.

        """
        def _match(ds_id, candidate_ds_id):
            return ds_id == candidate_ds_id

        self.data_sources[:] = [ds for ds in self.data_sources if not _match(ds.id, data_source_id)]

        return

    def remove_data_sources(self, data_source_ids):
        """Remove DataSources from the CompositeDataSource instance

        Args:
            data_source_ids (list): DataSource IDs

        """
        for ds_id in data_source_ids:
            self.remove_data_source(ds_id)
        return

    def has_data_sources(self):
        return len(self.data_sources)

    def get_all_data_sources(self):
        return self.data_sources
