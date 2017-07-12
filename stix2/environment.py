
class ObjectFactory(object):

    def __init__(self, created_by=None, markings=None):
        self.created_by = created_by
        self.markings = markings

    def create(self, cls=None, **kwargs):
        if cls is None:
            raise ValueError('No STIX object class provided')

        if self.created_by is not None:
            kwargs['created_by_ref'] = self.created_by
        if self.markings is not None:
            kwargs['object_marking_refs'] = self.markings

        return cls(**kwargs)
