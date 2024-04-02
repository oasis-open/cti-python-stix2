import re

# _ALLOWABLE_CLASSES = get_all_subclasses(_STIXBase21)
#
#
# _ALLOWABLE_CLASSES.extend(get_all_subclasses(Property))


def create_real_method_name(name, klass_name):
    # if klass_name not in _ALLOWABLE_CLASSES:
    #     raise NameError
    split_up_klass_name = re.findall('[A-Z][^A-Z]*', klass_name)
    return name + "_" + "_".join([x.lower() for x in split_up_klass_name])


def add_method(cls):
    def decorator(fn):
        method_name = fn.__name__
        fn.__name__ = create_real_method_name(fn.__name__, cls.__name__)
        setattr(cls, method_name, fn)
        return fn
    return decorator
