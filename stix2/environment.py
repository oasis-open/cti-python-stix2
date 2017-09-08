import copy

from .sources import CompositeDataSource


class ObjectFactory(object):
    """Easily create STIX objects with default values for certain properties.

    Args:
        created_by_ref: Default created_by_ref value to apply to all
            objects created by this factory.
        created: Default created value to apply to all
            objects created by this factory.
        external_references: Default `external_references` value to apply
            to all objects created by this factory.
        object_marking_refs: Default `object_marking_refs` value to apply
            to all objects created by this factory.
        list_append: When a default is set for a list property like
            `external_references` or `object_marking_refs` and a value for
            that property is passed into `create()`, if this is set to True,
            that value will be added to the list alongside the default. If
            this is set to False, the passed in value will replace the
            default. Defaults to True.
    """

    def __init__(self, created_by_ref=None, created=None,
                 external_references=None, object_marking_refs=None,
                 list_append=True):

        self._defaults = {}
        if created_by_ref:
            self._defaults['created_by_ref'] = created_by_ref
        if created:
            self._defaults['created'] = created
            # If the user provides a default "created" time, we also want to use
            # that as the modified time.
            self._defaults['modified'] = created
        if external_references:
            self._defaults['external_references'] = external_references
        if object_marking_refs:
            self._defaults['object_marking_refs'] = object_marking_refs
        self._list_append = list_append
        self._list_properties = ['external_references', 'object_marking_refs']

    def create(self, cls, **kwargs):
        # Use self.defaults as the base, but update with any explicit args
        # provided by the user.
        properties = copy.deepcopy(self._defaults)
        if kwargs:
            if self._list_append:
                # Append provided items to list properties instead of replacing them
                for list_prop in set(self._list_properties).intersection(kwargs.keys(), properties.keys()):
                    kwarg_prop = kwargs.pop(list_prop)
                    if kwarg_prop is None:
                        del properties[list_prop]
                        continue
                    if not isinstance(properties[list_prop], list):
                        properties[list_prop] = [properties[list_prop]]

                    if isinstance(kwarg_prop, list):
                        properties[list_prop].extend(kwarg_prop)
                    else:
                        properties[list_prop].append(kwarg_prop)

            properties.update(**kwargs)

        return cls(**properties)


class Environment(object):
    """

    Args:
        factory (ObjectFactory): Factory for creating objects with common
            defaults for certain properties.
        store (DataStore): Data store providing the source and sink for the
            environment.
        source (DataSource): Source for retrieving STIX objects.
        sink (DataSink): Destination for saving STIX objects.
            Invalid if `store` is also provided.
    """

    def __init__(self, factory=ObjectFactory(), store=None, source=None, sink=None):
        self.factory = factory
        self.source = CompositeDataSource()
        if store:
            self.source.add_data_source(store.source)
            self.sink = store.sink
        if source:
            self.source.add_data_source(source)
        if sink:
            if store:
                raise ValueError("Data store already provided! Environment may only have one data sink.")
            self.sink = sink

    def create(self, *args, **kwargs):
        """Use the object factory to create a STIX object with default property values.
        """
        return self.factory.create(*args, **kwargs)

    def get(self, *args, **kwargs):
        """Retrieve the most recent version of a single STIX object by ID.
        """
        try:
            return self.source.get(*args, **kwargs)
        except AttributeError:
            raise AttributeError('Environment has no data source to query')

    def all_versions(self, *args, **kwargs):
        """Retrieve all versions of a single STIX object by ID.
        """
        try:
            return self.source.all_versions(*args, **kwargs)
        except AttributeError:
            raise AttributeError('Environment has no data source to query')

    def query(self, *args, **kwargs):
        """Retrieve STIX objects matching a set of filters.
        """
        try:
            return self.source.query(*args, **kwargs)
        except AttributeError:
            raise AttributeError('Environment has no data source to query')

    def add_filters(self, *args, **kwargs):
        """Add multiple filters to be applied to all queries for STIX objects from this environment.
        """
        try:
            return self.source.add_filters(*args, **kwargs)
        except AttributeError:
            raise AttributeError('Environment has no data source')

    def add_filter(self, *args, **kwargs):
        """Add a filter to be applied to all queries for STIX objects from this environment.
        """
        try:
            return self.source.add_filter(*args, **kwargs)
        except AttributeError:
            raise AttributeError('Environment has no data source')

    def add(self, *args, **kwargs):
        """Store a STIX object.
        """
        try:
            return self.sink.add(*args, **kwargs)
        except AttributeError:
            raise AttributeError('Environment has no data sink to put objects in')
