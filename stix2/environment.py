
class ObjectFactory(object):

    def __init__(self, created_by_ref=None, created=None,
                 external_references=None, object_marking_refs=None,
                 granular_markings=None):
        self.created_by_ref = created_by_ref
        self.created = created
        self.external_references = external_references
        self.object_marking_refs = object_marking_refs
        self.granular_markings = granular_markings

    def create(self, cls, **kwargs):
        if 'created_by_ref' not in kwargs and self.created_by_ref is not None:
            kwargs['created_by_ref'] = self.created_by_ref
        if 'created' not in kwargs and self.created is not None:
            kwargs['created'] = self.created
            if 'modified' not in kwargs:
                kwargs['modified'] = self.created
        if 'external_references' not in kwargs and self.external_references is not None:
            kwargs['external_references'] = self.external_references
        if 'object_marking_refs' not in kwargs and self.object_marking_refs is not None:
            kwargs['object_marking_refs'] = self.object_marking_refs
        if 'granular_markings' not in kwargs and self.granular_markings is not None:
            kwargs['granular_markings'] = self.granular_markings

        return cls(**kwargs)
