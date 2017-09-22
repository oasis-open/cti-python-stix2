"""
Python STIX 2.0 Sources

Classes:
    DataStore
    DataSink
    DataSource
    CompositeDataSource

Notes:
    Q: We have add_filters() but no remove_filter()

"""

import uuid

from six import iteritems

from stix2.sources.filters import (FILTER_OPS, FILTER_VALUE_TYPES,
                                   STIX_COMMON_FIELDS, STIX_COMMON_FILTERS_MAP)


def make_id():
    return str(uuid.uuid4())


def apply_common_filters(stix_objs, query):
    """Evaluate filters against a set of STIX 2.0 objects.

    Supports only STIX 2.0 common property fields

    Args:
        stix_objs (list): list of STIX objects to apply the query to

        query (set): set of filters (combined form complete query)

    Returns:
        (list): list of STIX objects that successfully evaluate against
            the query.

    """
    filtered_stix_objs = []

    # evaluate objects against filter
    for stix_obj in stix_objs:
        clean = True
        for filter_ in query:
            # skip filter as filter was identified (when added) as
            # not a common filter
            if filter_.field not in STIX_COMMON_FIELDS:
                raise ValueError("Error, field: {0} is not supported for filtering on.".format(filter_.field))

            # For properties like granular_markings and external_references
            # need to break the first property from the string.
            if "." in filter_.field:
                field = filter_.field.split(".")[0]
            else:
                field = filter_.field

            # check filter "field" is in STIX object - if cant be
            # applied due to STIX object, STIX object is discarded
            # (i.e. did not make it through the filter)
            if field not in stix_obj.keys():
                clean = False
                break

            match = STIX_COMMON_FILTERS_MAP[filter_.field.split('.')[0]](filter_, stix_obj)
            if not match:
                clean = False
                break
            elif match == -1:
                raise ValueError("Error, filter operator: {0} not supported for specified field: {1}".format(filter_.op, filter_.field))

        # if object unmarked after all filters, add it
        if clean:
            filtered_stix_objs.append(stix_obj)

    return filtered_stix_objs


def deduplicate(stix_obj_list):
    """Deduplicate a list of STIX objects to a unique set

    Reduces a set of STIX objects to unique set by looking
    at 'id' and 'modified' fields - as a unique object version
    is determined by the combination of those fields

    Args:
        stix_obj_list (list): list of STIX objects (dicts)

    Returns:
        A list with a unique set of the passed list of STIX objects.

    """
    unique_objs = {}

    for obj in stix_obj_list:
        unique_objs[(obj['id'], obj['modified'])] = obj

    return list(unique_objs.values())


class DataStore(object):
    """DataStore

    An implementer will create a concrete subclass from
    this class for the specific DataStore.

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
        self.id = make_id()
        self.source = source
        self.sink = sink

    def get(self, stix_id):
        """Retrieve the most recent version of a single STIX object by ID.

        Translate get() call to the appropriate DataSource call.

        Args:
            stix_id (str): the id of the STIX object to retrieve.

        Returns:
            stix_obj: the single most recent version of the STIX
                object specified by the "id".

        """
        return self.source.get(stix_id)

    def all_versions(self, stix_id):
        """Retrieve all versions of a single STIX object by ID.

        Implement: Translate all_versions() call to the appropriate DataSource call

        Args:
            stix_id (str): the id of the STIX object to retrieve.

        Returns:
            stix_objs (list): a list of STIX objects

        """
        return self.source.all_versions(stix_id)

    def query(self, query):
        """Retrieve STIX objects matching a set of filters.

        Implement: Specific data source API calls, processing,
        functionality required for retrieving query from the data source.

        Args:
            query (list): a list of filters (which collectively are the query)
                to conduct search on.

        Returns:
            stix_objs (list): a list of STIX objects

        """
        return self.source.query(query=query)

    def add(self, stix_objs):
        """Store STIX objects.

        Translates add() to the appropriate DataSink call.

        Args:
            stix_objs (list): a list of STIX objects
        """
        return self.sink.add(stix_objs)

    def add_filters(self, filters):
        """add query filters (to DataSource component)

        Translates add_filters() to appropriate DataSource call.

        Args:
            filters (list or Filter obj): Filters to be added to DataStore

        """
        return self.source.add_filters(filters)


class DataSink(object):
    """DataSink

    An implementer will create a concrete subclass from
    this class for the specific DataSink.

    Attributes:
        id (str): A unique UUIDv4 to identify this DataSink.

    """
    def __init__(self):
        self.id = make_id()

    def add(self, stix_objs):
        """Store STIX objects.

        Implement: Specific data sink API calls, processing,
        functionality required for adding data to the sink

        Args:
            stix_objs (list): a list of STIX objects (where each object is a
                STIX object)

        """
        raise NotImplementedError()


class DataSource(object):
    """DataSource

    An implementer will create a concrete subclass from
    this class for the specific DataSource.

    Attributes:
        id (str): A unique UUIDv4 to identify this DataSource.

        _filters (set): A collection of filters attached to this DataSource.

    """
    def __init__(self):
        self.id = make_id()
        self._filters = set()

    def get(self, stix_id, _composite_filters=None):
        """
        Implement: Specific data source API calls, processing,
        functionality required for retrieving data from the data source

        Args:
            stix_id (str): the id of the STIX 2.0 object to retrieve. Should
                return a single object, the most recent version of the object
                specified by the "id".

            _composite_filters (set): set of filters passed from the parent
                the CompositeDataSource, not user supplied

        Returns:
            stix_obj: the STIX object

        """
        raise NotImplementedError()

    def all_versions(self, stix_id, _composite_filters=None):
        """
        Implement: Similar to get() except returns list of all object versions of
        the specified "id". In addition, implement the specific data
        source API calls, processing, functionality required for retrieving
        data from the data source.

        Args:
            stix_id (str): The id of the STIX 2.0 object to retrieve. Should
                return a list of objects, all the versions of the object
                specified by the "id".

            _composite_filters (set): set of filters passed from the parent
                CompositeDataSource, not user supplied

        Returns:
            stix_objs (list): a list of STIX objects

        """
        raise NotImplementedError()

    def query(self, query, _composite_filters=None):
        """
        Implement:Implement the specific data source API calls, processing,
        functionality required for retrieving query from the data source

        Args:
            query (list): a list of filters (which collectively are the query)
                to conduct search on

            _composite_filters (set): a set of filters passed from the parent
                CompositeDataSource, not user supplied

        Returns:
            stix_objs (list): a list of STIX objects

        """
        raise NotImplementedError()

    def add_filters(self, filters):
        """Add a filter to be applied to all queries for STIX objects.

        Args:
            filters (list or Filter obj): filter(s) to add to the Data Source.

        """
        if isinstance(filters, list) or isinstance(filters, set):
            for filter_ in filters:
                self.add_filters(filter_)
        else:
            filter_ = filters
            # check filter field is a supported STIX 2.0 common field
            if filter_.field not in STIX_COMMON_FIELDS:
                raise ValueError("Filter 'field' is not a STIX 2.0 common property. Currently only STIX object common properties supported")

            # check filter operator is supported
            if filter_.op not in FILTER_OPS:
                raise ValueError("Filter operation (from 'op' field) not supported")

            # check filter value type is supported
            if type(filter_.value) not in FILTER_VALUE_TYPES:
                raise ValueError("Filter 'value' type is not supported. The type(value) must be python immutable type or dictionary")

            self._filters.add(filter_)


class CompositeDataSource(DataSource):
    """CompostiteDataSource

    Controller for all the attached DataSources.

    A user can have a single CompositeDataSource as an interface
    the a set of DataSources. When an API call is made to the
    CompositeDataSource, it is delegated to each of the (real)
    DataSources that are attached to it.

    DataSources can be attached to CompositeDataSource for a variety
    of reasons, e.g. common filters, organization, less API calls.

    Attributes:
        name (str): The name that identifies this CompositeDataSource.

        data_sources (dict): A dictionary of DataSource objects; to be
            controlled and used by the Data Source Controller object.

    """
    def __init__(self):
        """Create a new STIX Data Source.

        Args:
            name (str): A string containing the name to attach in the
                CompositeDataSource instance.

        """
        super(CompositeDataSource, self).__init__()
        self.data_sources = {}

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
                to another parent CompositeDataSource), not user supplied

        Returns:
            stix_obj: the STIX object to be returned.

        """
        if not self.get_all_data_sources():
            raise AttributeError('CompositeDataSource has no data sources')

        all_data = []
        all_filters = set()
        all_filters.update(self._filters)

        if _composite_filters:
            all_filters.update(_composite_filters)

        # for every configured Data Source, call its retrieve handler
        for ds_id, ds in iteritems(self.data_sources):
            data = ds.get(stix_id=stix_id, _composite_filters=all_filters)
            all_data.append(data)

        # remove duplicate versions
        if len(all_data) > 0:
            all_data = deduplicate(all_data)

        # reduce to most recent version
        stix_obj = sorted(all_data, key=lambda k: k['modified'], reverse=True)[0]

        return stix_obj

    def all_versions(self, stix_id, _composite_filters=None):
        """Retrieve STIX objects by STIX ID

        Federated all_versions retrieve method - iterates through all DataSources
        defined in "data_sources"

        A composite data source will pass its attached filters to
        each configured data source, pushing filtering to them to handle

        Args:
            stix_id (str): id of the STIX objects to retrieve

            _composite_filters (list): a list of filters passed from a
                CompositeDataSource (i.e. if this CompositeDataSource is attached
                to a parent CompositeDataSource), not user supplied

        Returns:
            all_data (list): list of STIX objects that have the specified id

        """
        if not self.get_all_data_sources():
            raise AttributeError('CompositeDataSource has no data sources')

        all_data = []
        all_filters = set()

        all_filters.update(self._filters)

        if _composite_filters:
            all_filters.update(_composite_filters)

        # retrieve STIX objects from all configured data sources
        for ds_id, ds in iteritems(self.data_sources):
            data = ds.all_versions(stix_id=stix_id, _composite_filters=all_filters)
            all_data.extend(data)

        # remove exact duplicates (where duplicates are STIX 2.0 objects
        # with the same 'id' and 'modified' values)
        if len(all_data) > 0:
            all_data = deduplicate(all_data)

        return all_data

    def query(self, query=None, _composite_filters=None):
        """Retrieve STIX objects that match query

        Federate the query to all DataSources attached to the
        Composite Data Source.

        Args:
            query (list): list of filters to search on

            _composite_filters (list): a list of filters passed from a
                CompositeDataSource (i.e. if this CompositeDataSource is attached
                to a parent CompositeDataSource), not user supplied

        Returns:
            all_data (list): list of STIX objects to be returned

        """
        if not self.get_all_data_sources():
            raise AttributeError('CompositeDataSource has no data sources')

        if not query:
            # dont mess with the query (i.e. convert to a set, as thats done
            # within the specific DataSources that are called)
            query = []

        all_data = []

        all_filters = set()
        all_filters.update(self._filters)

        if _composite_filters:
            all_filters.update(_composite_filters)

        # federate query to all attached data sources,
        # pass composite filters to id
        for ds_id, ds in iteritems(self.data_sources):
            data = ds.query(query=query, _composite_filters=all_filters)
            all_data.extend(data)

        # remove exact duplicates (where duplicates are STIX 2.0
        # objects with the same 'id' and 'modified' values)
        if len(all_data) > 0:
            all_data = deduplicate(all_data)

        return all_data

    def add_data_source(self, data_sources):
        """Attach a DataSource to the CompositeDataSource instance

        Args:
            data_sources (list): a list of DataSource(s) to attach
                to the CompositeDataSource

        """
        if not isinstance(data_sources, list):
            data_sources = [data_sources]
        for ds in data_sources:
            if issubclass(ds.__class__, DataSource):
                if ds.id in self.data_sources:
                    # DataSource already attached to CompositeDataSource
                    continue

                # add DataSource to CompositeDataSource, its ID is used as key
                self.data_sources[ds.id] = ds
            else:
                # the Data Source object not a subclass of DataSource
                # TODO: maybe log error?
                continue

        return

    def remove_data_source(self, data_source_ids):
        """Remove DataSource from the CompositeDataSource instance

        Args:
            data_source_ids (list): a list of Data Source id(s).

        """
        for id in data_source_ids:
            if id in self.data_sources:
                del self.data_sources[id]
            else:
                raise ValueError("DataSource 'id' not found in CompositeDataSource.data_sources ")
        return

    def get_all_data_sources(self):
        """Return all attached DataSource(s)"""
        return self.data_sources.values()
