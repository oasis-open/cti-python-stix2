
class ObjectFactory(object):

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
        properties = dict(**self._defaults)
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
                    properties[list_prop].append(kwarg_prop)

            properties.update(**kwargs)

        return cls(**properties)
