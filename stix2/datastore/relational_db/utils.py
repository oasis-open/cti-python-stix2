import inflection

# Helps us know which data goes in core, and which in a type-specific table.
SCO_COMMON_PROPERTIES = {
    "id",
    "type",
    "spec_version",
    "object_marking_refs",
    "granular_markings",
    "defanged",
}

# Helps us know which data goes in core, and which in a type-specific table.
SDO_COMMON_PROPERTIES = {
    "id",
    "type",
    "spec_version",
    "object_marking_refs",
    "granular_markings",
    "defanged",
    "created",
    "modified",
    "created_by_ref",
    "revoked",
    "labels",
    "confidence",
    "lang",
    "external_references",
}


def canonicalize_table_name(table_name, schema_name=None):
    if schema_name:
        full_name = schema_name + "." + table_name
    else:
        full_name = table_name
    full_name = full_name.replace("-", "_")
    return inflection.underscore(full_name)
