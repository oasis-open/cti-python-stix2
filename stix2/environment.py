"""Python STIX2 Environment API."""
import copy

from .datastore import CompositeDataSource, DataStoreMixin
from .equivalence.graph import graphically_equivalent
from .equivalence.object import (  # noqa: F401
    WEIGHTS, check_property_present, custom_pattern_based, exact_match,
    list_reference_check, partial_external_reference_based, partial_list_based,
    partial_location_distance, partial_string_based, partial_timestamp_based,
    reference_check, semantically_equivalent,
)
from .parsing import parse as _parse

# TODO: Remove all unused imports that now belong to the equivalence module in the next major release.
# Kept for backwards compatibility.


class ObjectFactory(object):
    """Easily create STIX objects with default values for certain properties.

    Args:
        created_by_ref (optional): Default created_by_ref value to apply to all
            objects created by this factory.
        created (optional): Default created value to apply to all
            objects created by this factory.
        external_references (optional): Default `external_references` value to apply
            to all objects created by this factory.
        object_marking_refs (optional): Default `object_marking_refs` value to apply
            to all objects created by this factory.
        list_append (bool, optional): When a default is set for a list property like
            `external_references` or `object_marking_refs` and a value for
            that property is passed into `create()`, if this is set to True,
            that value will be added to the list alongside the default. If
            this is set to False, the passed in value will replace the
            default. Defaults to True.
    """

    def __init__(
        self, created_by_ref=None, created=None,
        external_references=None, object_marking_refs=None,
        list_append=True,
    ):

        self._defaults = {}
        if created_by_ref:
            self.set_default_creator(created_by_ref)
        if created:
            self.set_default_created(created)
        if external_references:
            self.set_default_external_refs(external_references)
        if object_marking_refs:
            self.set_default_object_marking_refs(object_marking_refs)
        self._list_append = list_append
        self._list_properties = ['external_references', 'object_marking_refs']

    def set_default_creator(self, creator=None):
        """Set default value for the `created_by_ref` property.

        """
        self._defaults['created_by_ref'] = creator

    def set_default_created(self, created=None):
        """Set default value for the `created` property.

        """
        self._defaults['created'] = created
        # If the user provides a default "created" time, we also want to use
        # that as the modified time.
        self._defaults['modified'] = created

    def set_default_external_refs(self, external_references=None):
        """Set default external references.

        """
        self._defaults['external_references'] = external_references

    def set_default_object_marking_refs(self, object_marking_refs=None):
        """Set default object markings.

        """
        self._defaults['object_marking_refs'] = object_marking_refs

    def create(self, cls, **kwargs):
        """Create a STIX object using object factory defaults.

        Args:
            cls: the python-stix2 class of the object to be created (eg. Indicator)
            **kwargs: The property/value pairs of the STIX object to be created
        """

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


class Environment(DataStoreMixin):
    """Abstract away some of the nasty details of working with STIX content.

    Args:
        factory (ObjectFactory, optional): Factory for creating objects with common
            defaults for certain properties.
        store (DataStore, optional): Data store providing the source and sink for the
            environment.
        source (DataSource, optional): Source for retrieving STIX objects.
        sink (DataSink, optional): Destination for saving STIX objects.
            Invalid if `store` is also provided.

    .. automethod:: get
    .. automethod:: all_versions
    .. automethod:: query
    .. automethod:: creator_of
    .. automethod:: relationships
    .. automethod:: related_to
    .. automethod:: add

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
        return self.factory.create(*args, **kwargs)
    create.__doc__ = ObjectFactory.create.__doc__

    def set_default_creator(self, *args, **kwargs):
        return self.factory.set_default_creator(*args, **kwargs)
    set_default_creator.__doc__ = ObjectFactory.set_default_creator.__doc__

    def set_default_created(self, *args, **kwargs):
        return self.factory.set_default_created(*args, **kwargs)
    set_default_created.__doc__ = ObjectFactory.set_default_created.__doc__

    def set_default_external_refs(self, *args, **kwargs):
        return self.factory.set_default_external_refs(*args, **kwargs)
    set_default_external_refs.__doc__ = ObjectFactory.set_default_external_refs.__doc__

    def set_default_object_marking_refs(self, *args, **kwargs):
        return self.factory.set_default_object_marking_refs(*args, **kwargs)
    set_default_object_marking_refs.__doc__ = ObjectFactory.set_default_object_marking_refs.__doc__

    def add_filters(self, *args, **kwargs):
        return self.source.filters.add(*args, **kwargs)

    def add_filter(self, *args, **kwargs):
        return self.source.filters.add(*args, **kwargs)

    def parse(self, *args, **kwargs):
        return _parse(*args, **kwargs)
    parse.__doc__ = _parse.__doc__

    def creator_of(self, obj):
        """Retrieve the Identity refered to by the object's `created_by_ref`.

        Args:
            obj: The STIX object whose `created_by_ref` property will be looked
                up.

        Returns:
            str: The STIX object's creator, or None, if the object contains no
                `created_by_ref` property or the object's creator cannot be
                found.

        """
        creator_id = obj.get('created_by_ref', '')
        if creator_id:
            return self.get(creator_id)
        else:
            return None

    @staticmethod
    def semantically_equivalent(obj1, obj2, prop_scores={}, **weight_dict):
        """This method verifies if two objects of the same type are
        semantically equivalent.

        Args:
            obj1: A stix2 object instance
            obj2: A stix2 object instance
            prop_scores: A dictionary that can hold individual property scores,
                weights, contributing score, matching score and sum of weights.
            weight_dict: A dictionary that can be used to override settings
                in the semantic equivalence process

        Returns:
            float: A number between 0.0 and 100.0 as a measurement of equivalence.

        Warning:
            Object types need to have property weights defined for the equivalence process.
            Otherwise, those objects will not influence the final score. The WEIGHTS
            dictionary under `stix2.equivalence.object` can give you an idea on how to add
            new entries and pass them via the `weight_dict` argument. Similarly, the values
            or methods can be fine tuned for a particular use case.

        Note:
            Default weight_dict:

            .. include:: ../object_default_sem_eq_weights.rst

        Note:
            This implementation follows the Semantic Equivalence Committee Note.
            see `the Committee Note <link here>`__.

        """
        return semantically_equivalent(obj1, obj2, prop_scores, **weight_dict)

    @staticmethod
    def graphically_equivalent(ds1, ds2, prop_scores={}, **weight_dict):
        """This method verifies if two graphs are semantically equivalent.
        Each DataStore can contain a connected or disconnected graph and the
        final result is weighted over the amount of objects we managed to compare.
        This approach builds on top of the object-based semantic equivalence process
        and each comparison can return a value between 0 and 100.

        Args:
            ds1: A DataStore object instance representing your graph
            ds2: A DataStore object instance representing your graph
            prop_scores: A dictionary that can hold individual property scores,
                weights, contributing score, matching score and sum of weights.
            weight_dict: A dictionary that can be used to override settings
                in the semantic equivalence process

        Returns:
            float: A number between 0.0 and 100.0 as a measurement of equivalence.

        Warning:
            Object types need to have property weights defined for the equivalence process.
            Otherwise, those objects will not influence the final score. The WEIGHTS
            dictionary under `stix2.equivalence.graph` can give you an idea on how to add
            new entries and pass them via the `weight_dict` argument. Similarly, the values
            or methods can be fine tuned for a particular use case.

        Note:
            Default weight_dict:

            .. include:: ../graph_default_sem_eq_weights.rst

        Note:
            This implementation follows the Semantic Equivalence Committee Note.
            see `the Committee Note <link here>`__.

        """
        return graphically_equivalent(ds1, ds2, prop_scores, **weight_dict)
