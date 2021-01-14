import importlib
import pkgutil
import re

# Collects information on which classes implement which STIX types, for the
# various STIX spec versions.
STIX2_OBJ_MAPS = {}


def _stix_vid_to_version(stix_vid):
    """
    Convert a python package name representing a STIX version in the form "vXX"
    to the dotted style used in the public APIs of this library, "X.X".

    :param stix_vid: A package name in the form "vXX"
    :return: A STIX version in dotted style
    """
    assert len(stix_vid) >= 3

    stix_version = stix_vid[1] + "." + stix_vid[2:]
    return stix_version


def _collect_stix2_mappings():
    """Navigate the package once and retrieve all object mapping dicts for each
    v2X package. Includes OBJ_MAP, OBJ_MAP_OBSERVABLE, EXT_MAP."""
    if not STIX2_OBJ_MAPS:
        top_level_module = importlib.import_module('stix2')
        path = top_level_module.__path__
        prefix = str(top_level_module.__name__) + '.'

        for module_loader, name, is_pkg in pkgutil.walk_packages(path=path, prefix=prefix):
            stix_vid = name.split('.')[1]
            if re.match(r'^stix2\.v2[0-9]$', name) and is_pkg:
                ver = _stix_vid_to_version(stix_vid)
                mod = importlib.import_module(name, str(top_level_module.__name__))
                STIX2_OBJ_MAPS[ver] = {}
                STIX2_OBJ_MAPS[ver]['objects'] = mod.OBJ_MAP
                STIX2_OBJ_MAPS[ver]['observables'] = mod.OBJ_MAP_OBSERVABLE
                STIX2_OBJ_MAPS[ver]['observable-extensions'] = mod.EXT_MAP
            elif re.match(r'^stix2\.v2[0-9]\.common$', name) and is_pkg is False:
                ver = _stix_vid_to_version(stix_vid)
                mod = importlib.import_module(name, str(top_level_module.__name__))
                STIX2_OBJ_MAPS[ver]['markings'] = mod.OBJ_MAP_MARKING
