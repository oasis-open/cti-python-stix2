
class ObjectFactory(object):

    def __init__(self, created_by=None, object_markings=None,
                 granular_markings=None, external_references=None):
        self.created_by = created_by
        self.object_markings = object_markings
        self.granular_markings = granular_markings
        self.external_references = external_references

    def create(self, cls, **kwargs):
        if self.created_by is not None:
            kwargs['created_by_ref'] = self.created_by
        if self.object_markings is not None:
            kwargs['object_marking_refs'] = self.object_markings
        if self.granular_markings is not None:
            kwargs['granular_markings'] = self.granular_markings
        if self.external_references is not None:
            kwargs['external_references'] = self.external_references

        return cls(**kwargs)
