
class ObjectPathComponent(object):
    pass


class BasicObjectPathComponent(ObjectPathComponent):
    def __init__(self, property_name, is_key=False):
        self.property_name = property_name
        # TODO: set is_key to True if this component is a dictionary key
        # self.is_key = is_key

    def __str__(self):
        return self.property_name


class ListObjectPathComponent(ObjectPathComponent):
    def __init__(self, property_name, index):
        self.property_name = property_name
        self.index = index

    def __str__(self):
        return "%s[%s]" % (self.property_name, self.index)


class ReferenceObjectPathComponent(ObjectPathComponent):
    def __init__(self, reference_property_name):
        self.property_name = reference_property_name

    def __str__(self):
        return self.property_name


class ObjectPath(object):
    def __init__(self, object_type_name, property_path):
        self.object_type_name = object_type_name
        self.property_path = [x if isinstance(x, ObjectPathComponent) else ObjectPath.create_ObjectPathComponent(x)
                              for x in property_path]

    def __str__(self):
        return "%s:%s" % (self.object_type_name, ".".join(["%s" % x for x in self.property_path]))

    def merge(self, other):
        self.property_path.extend(other.property_path)
        return self

    @staticmethod
    def make_object_path(lhs):
        path_as_parts = lhs.split(":")
        return ObjectPath(path_as_parts[0], path_as_parts[1].split("."))

    @staticmethod
    def create_ObjectPathComponent(component_name):
        if component_name.endswith("_ref"):
            return ReferenceObjectPathComponent(component_name)
        elif component_name.find("[") != -1:
            parse1 = component_name.split("[")
            return ListObjectPathComponent(parse1[0], parse1[1][:-1])
        else:
            return BasicObjectPathComponent(component_name)
