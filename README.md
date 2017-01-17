# stix2

Create, parse, and interact with STIX 2 JSON content.

## Installation

Install with [`pip`](https://pip.pypa.io/en/stable/):

```
pip install stix2
```

## Usage


### Creating STIX Domain Objects

To create a STIX object, provide keyword arguments to the type's constructor:

```python
from stix2 import Indicator

indicator = Indicator(name="File hash for malware variant",
                      labels=['malicious-activity'],
                      pattern='file:hashes.md5 = "d41d8cd98f00b204e9800998ecf8427e"')

```

Certain required attributes of all objects will be set automatically if not
provided as keyword arguments:

- If not provided, `type` will be set automatically to the correct type.
  You can also provide the type explicitly, but this is not necessary:

  ```python
  indicator = Indicator(type='indicator', ...)
  ```

  Passing a value for `type` that does not match the class being constructed
  will cause an error:

  ```python
  >>> indicator = Indicator(type='xxx', ...)
  ValueError: Indicators must have type='indicator'
  ```

- If not provided, `id` will be generated randomly. If you provide an `id`
  argument, it must begin with the correct prefix:

  ```python
  >>> indicator = Indicator(id="campaign--63ce9068-b5ab-47fa-a2cf-a602ea01f21a")
  ValueError: Indicator id values must begin with 'indicator--'
  ```

- If not provided, `created` and `modified` will be set to the (same) current
  time.

For indicators, `labels` and `pattern` are required and cannot be set
automatically. Trying to create an indicator that is missing one of these fields
will result in an error:

```python
>>> indicator = Indicator()
ValueError: Missing required field for Indicator: 'labels'
```

However, the required `valid_from` attribute on Indicators will be set to the
current time if not provided as a keyword argument.

Once created, the object acts like a frozen dictionary. Properties can be
accessed using the standard Python dictionary syntax:

```python
>>> indicator['name']
'File hash for malware variant'
```

TBD: Should we allow property access using the standard Python attribute syntax?

```python
>>> indicator.name
'File hash for malware variant'
```

Attempting to modify any attributes will raise an error:

```python
>>>indicator['name'] = "This is a revised name"
ValueError: Cannot modify properties after creation.
```

To update the properties of an object, see [Versioning](#versioning) below.

Creating a Malware object follows the same pattern:

```python
from stix2 import Malware

malware = Malware(name="Poison Ivy",
                  labels=['remote-access-trojan'])
```

As with indicators, the `type`, `id`, `created`, and `modified` properties will
be set automatically if not provided. For Malware objects, the `labels` and
`name` properties must be provided.

### Creating Relationships

STIX 2 Relationships are separate objects, not properties of the object on
either side of the relationship. They are constructed similarly to other STIX
objects. The `type`, `id`, `created`, and `modified` properties are added
automatically if not provided. Callers must provide the `relationship_type`,
`source_ref`, and `target_ref` properties.

```python
from stix2 import Relationship

relationship = Relationship(relationship_type='indicates',
                            source_ref=indicator.id,
                            target_ref=malware.id)
```

The `source_ref` and `target_ref` properties can be either the ID's of other
STIX objects, or the STIX objects themselves. For readability, Relationship
objects can also be constructed with the `source_ref`, `relationship_type`, and
`target_ref` as positional (non-keyword) arguments:

```python
relationship = Relationship(indicator, 'indicates', malware)
```

### Creating Bundles

STIX Bundles can be created by passing objects as arguments to the Bundle
constructor. All required properties (`type`, `id`, and `spec_version`) will be
set automatically if not provided, or can be provided as keyword arguments:

```
from stix2 import bundle

bundle = Bundle(indicator, malware, relationship)
```

### Serializing STIX objects

TBD

### Versioning

TBD
