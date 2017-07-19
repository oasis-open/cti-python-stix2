"""
Python STIX 2.0 Sources

Classes:
    DataStore
    DataSink
    DataSource
    STIXCommonPropertyFilters

TODO:Test everything

NOTE: add_filter(), remove_filter(), deduplicate() - if these functions remain
      the exact same for DataSource, DataSink, CompositeDataSource etc... -> just
      make those functions an interface to inherit?
"""

import copy
import uuid

from six import iteritems


def make_id():
    return str(uuid.uuid4())


# STIX 2.0 fields used to denote object version
STIX_VERSION_FIELDS = ['id', 'modified']

# Currently, only STIX 2.0 common SDO fields (that are not compex objects)
# are supported for filtering on
STIX_COMMON_FIELDS = [
    "created",
    "created_by_ref",
    "external_references.source_name",
    "external_references.description",
    "external_references.url",
    "external_references.hashes",
    "external_references.external_id",
    "granular_markings.marking_ref",
    "granular_markings.selectors",
    "id",
    "labels",
    "modified",
    "object_marking_refs",
    "revoked",
    "type",
    "granular_markings"
]


# Required fields in filter(dict)
FILTER_FIELDS = ['field', 'op', 'value']

# Supported filter operations
FILTER_OPS = ['=', '!=', 'in', '>', '<', '>=', '<=']

# Supported filter value types
FILTER_VALUE_TYPES = [bool, dict, float, int, list, str, tuple]


class DataStore(object):
    """
    An implementer will create a concrete subclass from
    this abstract class for the specific data store.
    """
    def __init__(self, name="DataStore"):
        self.name = name
        self.id = make_id()
        self.source = None
        self.sink = None

    def get(self, stix_id):
        """
        Implement:
            -translate API get() call to the appropriate DataSource call

        Args:

            stix_id (str): the id of the STIX 2.0 object to retrieve. Should
                return a single object, the most recent version of the object
                specified by the "id".

            _composite_filters (list): list of filters passed along from
                the Composite Data Filter.

        Returns:
            stix_obj (dictionary): the STIX object to be returned
        """
        return self.source.get(stix_id=stix_id)

    def all_versions(self, stix_id):
        """
        Implement:
            -translate all_versions() call to the appropriate DataSource call

        Args:

            stix_id (str): the id of the STIX 2.0 object to retrieve. Should
                return a single object, the most recent version of the object
                specified by the "id".

            _composite_filters (list): list of filters passed along from
                the Composite Data Filter.

        Returns:
            stix_objs (list): a list of STIX objects (where each object is a
                STIX object)
        """
        return self.source.all_versions(stix_id=stix_id)

    def query(self, query):
        """
        Fill:
            -implement the specific data source API calls, processing,
            functionality required for retrieving query from the data source

        Args:
            query (list): a list of filters (which collectively are the query)
                to conduct search on

            _composite_filters (list): a list of filters passed from the
                Composite Data Source

        Returns:
            stix_objs (list): a list of STIX objects (where each object is a
                STIX object)

        """
        return self.source.query(query=query)

    def add(self, stix_objs):
        """
        Fill:
            -translate add() to the appropriate DataSink call()

        """
        return self.sink.add(stix_objs=stix_objs)


class DataSink(object):
    """
    An implementer will create a concrete subclass from this
    abstract class for the specific data sink.
    """

    def __init__(self, name="DataSink"):
        self.name = name
        self.id = make_id()

    def add(self, stix_objs):
        """
        Fill:
            -implement the specific data sink API calls, processing,
            functionality required for adding data to the sink
        """
        raise NotImplementedError()


class DataSource(object):
    """
    An implementer will create a concrete subclass from
    this abstract class for the specific data source.
    """

    def __init__(self, name="DataSource"):
        self.name = name
        self.id = make_id()
        self.filters = {}
        self.filter_allowed = {}

    def get(self, stix_id, _composite_filters=None):
        """
        Fill:
            -implement the specific data source API calls, processing,
            functionality required for retrieving data from the data source

        Args:

            stix_id (str): the id of the STIX 2.0 object to retrieve. Should
                return a single object, the most recent version of the object
                specified by the "id".

            _composite_filters (list): list of filters passed along from
                the Composite Data Filter.

        Returns:
            stix_obj (dictionary): the STIX object to be returned

        """
        raise NotImplementedError()

    def all_versions(self, stix_id, _composite_filters=None):
        """
        Fill:
            -Similar to get() except returns list of all object versions of
                the specified "id".

            -implement the specific data source API calls, processing,
            functionality required for retrieving data from the data source

        Args:
            id (str): The id of the STIX 2.0 object to retrieve. Should
                return a list of objects, all the versions of the object
                specified by the "id".

            _composite_filters (list): list of filters passed from the
                Composite Data Source

        Returns:
            stix_objs (list): a list of STIX objects (where each object is a
                STIX object)
        """

        raise NotImplementedError()

    def query(self, query, _composite_filters=None):
        """
        Fill:
            -implement the specific data source API calls, processing,
            functionality required for retrieving query from the data source

        Args:
            query (list): a list of filters (which collectively are the query)
                to conduct search on

            _composite_filters (list): a list of filters passed from the
                Composite Data Source

        Returns:


        """

        raise NotImplementedError()

    def add_filter(self, filters):
        """add/attach a filter to the Data Source instance

        Args:
            filters (list): list of filters (dict) to add to the Data Source

        Returns:
            status (list): list of status/error messages

        """

        status = []
        errors = []
        ids = []
        allowed = True

        for filter_ in filters:
            # check required filter components ("field", "op", "value") exist
            for field in FILTER_FIELDS:
                if field not in filter_.keys():
                    allowed = False
                    errors.append("Filter was missing a required field(key). Each filter requires 'field', 'op', 'value' keys.")
                    break

            if allowed:
                # no need for further checks if filter is missing parameters

                # check filter field is a supported STIX 2.0 common field
                if filter_['field'] not in STIX_COMMON_FIELDS:
                    allowed = False
                    errors.append("Filter 'field' is not a STIX 2.0 common property. Currently only STIX object common properties supported")

                # check filter operator is supported
                if filter_['op'] not in FILTER_OPS:
                    allowed = False
                    errors.append("Filter operation(from 'op' field) not supported")

                # check filter value type is supported
                if type(filter_['value']) not in FILTER_VALUE_TYPES:
                    allowed = False
                    errors.append("Filter 'value' type is not supported. The type(value) must be python immutable type or dictionary")

            # Filter is added regardless of whether it fits requirements
            # to be a common filter. This is done because some filters
            # may be added and used by third party Data Sources, where the
            # filtering may be conducted within those plugins, just not here

            id_ = make_id()
            filter_['id'] = id_
            self.filters[id_] = filter_
            ids.append(id_)

            if allowed:
                self.filter_allowed[id_] = True
                status.append({
                        "status": "added as a common filter",
                        "filter": filter_,
                        "data_source_name": self.name,
                        "data_source_id": self.id_
                    })
            else:
                self.filter_allowed[id_] = False
                status.append({
                    "status": "added but is not a common filter",
                    "filter": filter_,
                    "errors": copy.deepcopy(errors),
                    "data_source_name": self.name,
                    "data_source_id": self.id_
                })
                del errors[:]

            allowed = True

        return ids, status

    def remove_filter(self, filter_ids):
        """remove/detach a filter from the Data Source instance

        Args:
            filter_ids (list): list of filter ids to dettach/remove
                from Data Source

        Returns:


        """
        for filter_id in filter_ids:
            try:
                if filter_id in self.filters:
                    del self.filters[filter_id]
                    del self.filter_allowed[filter_id]
            except KeyError:
                # filter 'id' not found list of filters attached to Data Source
                pass

        return

    def get_filters(self):
        """return copy of all filters currently attached to Data Source

        TODO: make this a property?

        Returns:
            (list): a copy of all the filters(dict) which are attached
                to Data Source

        """
        return copy.deepcopy(list(self.filters.values()))

    def apply_common_filters(self, stix_objs, query):
        """evaluates filters against a set of STIX 2.0 objects

        Supports only STIX 2.0 common property fields

        Args:
            stix_objs (list): list of STIX objects to apply the query to
            query (list): list of filters (combined form complete query)

        Returns:
            (list): list of STIX objects that successfully evaluate against
                the query

        """

        filtered_stix_objs = []

        # evaluate objects against filter
        for stix_obj in stix_objs:
            clean = True
            for filter_ in query:

                # skip filter as filter was identified (when added) as
                # not a common filter
                if 'id' in filter_ and self.filter_allowed[filter_['id']] is False:
                    continue

                # check filter "field" is in STIX object - if cant be applied
                # due to STIX object, STIX object is discarded (i.e. did not
                # make it through the filter)
                if filter_['field'] not in stix_obj.keys():
                    clean = False
                    break
                try:
                    match = getattr(STIXCommonPropertyFilters, filter_['field'])(filter_, stix_obj)
                    if not match:
                        clean = False
                        break
                    elif match == -1:
                        # error, filter operator not supported for specified field:
                        pass
                except Exception as e:
                    print(e)

            # if object unmarked after all filters, add it
            if clean:
                filtered_stix_objs.append(stix_obj)

        return filtered_stix_objs

    def deduplicate(self, stix_obj_list):
        """deduplicate a list of STIX objects into a unique set

        reduces a set of STIX objects to unique set by looking
        at 'id' and 'modified' fields - as a unique object version
        is determined by the combination of those fields

        Args:
            stix_obj_list (list): list of STIX objects (dicts)

        Returns:
            (list): a unique set of the passed STIX object list


        """
        unique = []
        have = False
        for i in stix_obj_list:
            for j in unique:
                if i['id'] == j['id'] and i['modified'] == j['modified']:
                    have = True
                    break
            if not have:
                unique.append(i)
            have = False
        return unique


class CompositeDataSource(object):
    """Composite Data Source

    Acts as a controller for all the defined/configured STIX Data Sources
    e.g. a user can defined n Data Sources - creating Data Source (objects)
    for each. There is only one instance of this for any python STIX 2.0
    application

    """
    def __init__(self, name="CompositeDataSource"):
        """
        Creates a new STIX Data Source.

        Args:
            'data_sources' (dict): a dict of DataSource objects; to be
                controlled and used by the Data Source Controller object

            filters :
            name :
        """
        self.id = make_id()
        self.name = name
        self.data_sources = {}
        self.filters = {}
        self.filter_allowed = {}

    def get(self, stix_id):
        """Retrieve STIX object by 'id'

        federated retrieve method-iterates through all STIX data sources
        defined in the "data_sources" parameter. Each data source has a
        specific API retrieve-like function and associated parameters. This
        function does a federated retrieval and consolidation of the data
        returned from all the STIX data sources.

        note: a composite data source will pass its attached filters to
        each configured data source, pushing filtering to them to handle

        Args:
            id (str): the id of the STIX object to retrieve

        Returns:
            stix_obj (dict): the STIX object to be returned

        """

        all_data = []

        # for every configured Data Source, call its retrieve handler
        for ds_id, ds in iteritems(self.data_sources):
            data = ds.get(stix_id=stix_id, _composite_filters=self.filters.values())
            all_data.extend(data)

        # remove duplicate versions
        if len(all_data) > 0:
            all_data = self.deduplicate(all_data)

        # reduce to most recent version
        stix_obj = sorted(all_data, key=lambda k: k['modified'])[0]

        return stix_obj

    def all_versions(self, stix_id):
        """Retrieve STIX objects by 'id'

        Federated all_versions retrieve method - iterates through all STIX data
        sources defined in "data_sources"

        note: a composite data source will pass its attached filters to
        each configured data source, pushing filtering to them to handle

        Args:
            id_ (str): id of the STIX objects to retrieve

        Returns:
            all_data (list): list of STIX objects that have the specified id
        """
        all_data = []

        # retrieve STIX objects from all configured data sources
        for ds_id, ds in iteritems(self.data_sources):
            data = ds.all_versions(stix_id=stix_id, _composite_filters=self.filters.values())
            all_data.extend(data)

        # remove exact duplicates (where duplicates are STIX 2.0 objects
        # with the same 'id' and 'modified' values)
        if len(all_data) > 0:
            all_data = self.deduplicate(all_data)

        return all_data

    def query(self, query=None):
        """composite data source query

        Federate the query to all Data Sources attached
        to the Composite Data Source

        Args:
            query (list): list of filters to search on

        Returns:
            all_data (list): list of STIX objects to be returned

        """
        if not query:
            query = []

        all_data = []

        # federate query to all attached data sources,
        # pass composite filters to id
        for ds_id, ds in iteritems(self.data_sources):
            data = ds.query(query=query, _composite_filters=self.filters.values())
            all_data.extend(data)

        # remove exact duplicates (where duplicates are STIX 2.0
        # objects with the same 'id' and 'modified' values)
        if len(all_data) > 0:
            all_data = self.deduplicate(all_data)

        return all_data

    def add_data_source(self, data_sources):
        """add/attach Data Source to the Composite Data Source instance

        Args:
            data_sources (list): a list of Data Source objects to attach
                to the Composite Data Source

        Returns:

        """

        for ds in data_sources:
            if issubclass(ds, DataSource):
                if self.data_sources[ds['id']] in self.data_sources.keys():
                    # data source already attached to Composite Data Source
                    continue

                # add data source to Composite Data Source
                # (its id will be its key identifier)
                self.data_sources[ds['id']] = ds
            else:
                # the Data Source object is not a proper subclass
                # of DataSource Abstract Class
                # TODO: maybe log error?
                continue

        return

    def remove_data_source(self, data_source_ids):
        """remove/detach Data Source from the Composite Data Source instance

        Args:
            data_source_ids (list): a list of Data Source
                id's(which are strings)

        Returns:

        """

        for id_ in data_source_ids:
            try:
                if self.data_sources[id_]:
                    del self.data_sources[id_]
            except KeyError:
                # Data Source 'id' was not found in CompositeDataSource's
                # list of data sources
                pass
        return

    @property
    def data_sources(self):
        """return all attached Data Sources

        Args:

        Returns:

        """
        return copy.deepcopy(self.data_sources.values())

    def add_filter(self, filters):
        """add/attach a filter to the Composite Data Source instance

        Args:
            filters (list): list of filters (dict) to add to the Data Source

        Returns:
            status (list): list of status/error messages

        """

        status = []
        errors = []
        ids = []
        allowed = True

        for filter_ in filters:
            # check required filter components ("field", "op", "value") exist
            for field in FILTER_FIELDS:
                if field not in filter_.keys():
                    allowed = False
                    errors.append("Filter was missing a required field(key). Each filter requires 'field', 'op', 'value' keys.")
                    break

            if allowed:
                # no need for further checks if filter is missing parameters

                # check filter field is a supported STIX 2.0 common field
                if filter_['field'] not in STIX_COMMON_FIELDS:
                    allowed = False
                    errors.append("Filter 'field' is not a STIX 2.0 common property. Currently only STIX object common properties supported")

                # check filter operator is supported
                if filter_['op'] not in FILTER_OPS:
                    allowed = False
                    errors.append("Filter operation(from 'op' field) not supported")

                # check filter value type is supported
                if type(filter_['value']) not in FILTER_VALUE_TYPES:
                    allowed = False
                    errors.append("Filter 'value' type is not supported. The type(value) must be python immutable type or dictionary")

            # Filter is added regardless of whether it fits requirements
            # to be a common filter. This is done because some filters
            # may be added and used by third party Data Sources, where the
            # filtering may be conducted within those plugins, just not here

            id_ = make_id()
            filter_['id'] = id_
            self.filters['id_'] = filter_
            ids.append(id_)

            if allowed:
                self.filter_allowed[id_] = True
                status.append({
                        "status": "added as a common filter",
                        "filter": filter_,
                        "data_source_name": self.name,
                        "data_source_id": self.id_
                    })
            else:
                self.filter_allowed[id_] = False
                status.append({
                    "status": "added but is not a common filter",
                    "filter": filter_,
                    "errors": errors,
                    "data_source_name": self.name,
                    "data_source_id": self.id_
                })
                del errors[:]

            allowed = True

        return ids, status

    def remove_filter(self, filter_ids):
        """Remove/detach a filter from the Data Source instance

        Args:
            filter_ids (list): list of filter id's (which are strings)
            dettach from the Composite Data Source

        Returns:

        """

        for filter_id in filter_ids:
            try:
                if filter_id in self.filters:
                    del self.filters[filter_id]
                    del self.filter_allowed[filter_id]
            except KeyError:
                # filter id not found in list of filters
                # attached to the Composite Data Source
                pass

        return

    @property
    def filters(self):
        """return filters attached to Composite Data Source

        Args:

        Returns:
            (list): the list of filters currently attached to the Data Source

        """
        return copy.deepcopy(list(self.filters.values()))

    def deduplicate(self, stix_obj_list):
        """deduplicate a list fo STIX objects to a unique set

        Reduces a set of STIX objects to unique set by looking
        at 'id' and 'modified' fields - as a unique object version
        is determined by the combination of those fields

        Args:
            stix_obj_list (list): list of STIX objects (dicts)

        Returns:
                (list): unique set of the passed list of STIX objects
        """

        unique = []
        dont_have = False
        for i in stix_obj_list:
            dont_have = False
            for j in unique:
                for field in STIX_VERSION_FIELDS:
                    if not i[field] == j[field]:
                        dont_have = True
                    break
            if dont_have:
                unique.append(i)
        return unique


class STIXCommonPropertyFilters():
    """
    """
    @classmethod
    def _all(cls, filter_, stix_obj_field):
        """all filter operations (for filters whose value type can be applied to any operation type)"""
        if filter_["op"] == '=':
            return stix_obj_field == filter_["value"]
        elif filter_["op"] == "!=":
            return stix_obj_field != filter_["value"]
        elif filter_["op"] == "in":
            return stix_obj_field in filter_["value"]
        elif filter_["op"] == ">":
            return stix_obj_field > filter_["value"]
        elif filter_["op"] == "<":
            return stix_obj_field < filter_["value"]
        elif filter_["op"] == ">=":
            return stix_obj_field >= filter_["value"]
        elif filter_["op"] == "<=":
            return stix_obj_field <= filter_["value"]
        else:
            return -1

    @classmethod
    def _id(cls, filter_, stix_obj_id):
        """base filter types"""
        if filter_["op"] == "=":
            return stix_obj_id == filter_["value"]
        elif filter_["op"] == "!=":
            return stix_obj_id != filter_["value"]
        else:
            return -1

    @classmethod
    def _boolean(filter_, stix_obj_field):
        if filter_["op"] == "=":
            return stix_obj_field == filter_["value"]
        elif filter_["op"] == "!=":
            return stix_obj_field != filter_["value"]
        else:
            return -1

    @classmethod
    def _string(cls, filter_, stix_obj_field):
        return cls._all(filter_, stix_obj_field)

    @classmethod
    def _timestamp(cls, filter_, stix_obj_timestamp):
        return cls._all(filter_, stix_obj_timestamp)

    # STIX 2.0 Common Property filters
    @classmethod
    def created(cls, filter_, stix_obj):
        return cls._timestamp(filter_, stix_obj["created"])

    @classmethod
    def created_by_ref(cls, filter_, stix_obj):
        return cls._id(filter_, stix_obj["created_by_ref"])

    @classmethod
    def external_references(cls, filter_, stix_obj):
        '''
        stix object's can have a list of external references

        external-reference properties:
            external_reference.source_name (string)
            external_reference.description (string)
            external_reference.url (string)
            external_reference.hashes (hash, but for filtering purposes , a string)
            external_reference.external_id  (string)
        '''
        for er in stix_obj["external_references"]:
            # grab er property name from filter field
            filter_field = filter_["field"].split(".")[1]
            r = cls._string(filter_, er[filter_field])
            if r:
                return r
        return False

    @classmethod
    def granular_markings(cls, filter_, stix_obj):
        '''
        stix object's can have a list of granular marking references

        granular-marking properties:
            granular-marking.marking_ref (id)
            granular-marking.selectors  (string)
        '''
        for gm in stix_obj["granular_markings"]:
            # grab gm property name from filter field
            filter_field = filter_["field"].split(".")[1]

            if filter_field == "marking_ref":
                return cls._id(filter_, gm[filter_field])

            elif filter_field == "selectors":
                for selector in gm[filter_field]:
                    r = cls._string(filter_, selector)
                    if r:
                        return r
        return False

    @classmethod
    def id(cls, filter_, stix_obj):
        return cls._id(filter_, stix_obj["id"])

    @classmethod
    def labels(cls, filter_, stix_obj):
        for label in stix_obj["labels"]:
            r = cls._string(filter_, label)
            if r:
                return r
        return False

    @classmethod
    def modified(cls, filter_, stix_obj):
        return cls._timestamp(filter_, stix_obj["created"])

    @classmethod
    def object_markings_ref(cls, filter_, stix_obj):
        for marking_id in stix_obj["object_market_refs"]:
            r = cls._id(filter_, marking_id)
            if r:
                return r
        return False

    @classmethod
    def revoked(cls, filter_, stix_obj):
        return cls._boolean(filter_, stix_obj["revoked"])

    @classmethod
    def type(cls, filter_, stix_obj):
        return cls._string(filter_, stix_obj["type"])
