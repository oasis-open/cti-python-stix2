
class ObjectFactory(object):

    def __init__(self, created_by_ref=None, created=None,
                 external_references=None, object_marking_refs=None,
                 granular_markings=None):

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
        if granular_markings:
            self._defaults['granular_markings'] = granular_markings

    def create(self, cls, **kwargs):
        # Use self.defaults as the base, but update with any explicit args
        # provided by the user.
        properties = dict(**self._defaults)
        if kwargs:
            properties.update(**kwargs)

        return cls(**properties)
