[![Build Status](https://travis-ci.org/oasis-open/cti-python-stix2.svg?branch=master)](https://travis-ci.org/oasis-open/cti-python-stix2)
[![codecov](https://codecov.io/gh/oasis-open/cti-python-stix2/branch/master/graph/badge.svg)](https://codecov.io/gh/oasis-open/cti-python-stix2)

# cti-python-stix2

*This is an [OASIS Open Repository](https://www.oasis-open.org/resources/open-repositories/). See the [Governance](#governance) section for more information.*

This repository provides Python APIs for serializing and de-serializing STIX 2 JSON content, along with higher-level APIs for common tasks, including data markings, versioning, and for resolving STIX IDs across multiple data sources.

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
  stix2.exceptions.InvalidValueError: Invalid value for Indicator 'type': must equal 'indicator'.
  ```

- If not provided, `id` will be generated randomly. If you provide an `id`
  argument, it must begin with the correct prefix:

  ```python
  >>> indicator = Indicator(id="campaign--63ce9068-b5ab-47fa-a2cf-a602ea01f21a")
  stix2.exceptions.InvalidValueError: Invalid value for Indicator 'id': must start with 'indicator--'.
  ```

- If not provided, `created` and `modified` will be set to the (same) current
  time.

For indicators, `labels` and `pattern` are required and cannot be set
automatically. Trying to create an indicator that is missing one of these
properties will result in an error:

```python
>>> indicator = Indicator()
stix2.exceptions.MissingPropertiesError: No values for required properties for Indicator: (labels, pattern).
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
>>> indicator['name'] = "This is a revised name"
TypeError: 'Indicator' object does not support item assignment
>>> indicator.name = "This is a revised name"
stix2.exceptions.ImmutableError: Cannot modify properties after creation.
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

```python
from stix2 import bundle

bundle = Bundle(indicator, malware, relationship)
```

### Serializing STIX objects

The string representation of all STIX classes is a valid STIX JSON object.

```python
indicator = Indicator(...)

print(str(indicator))
```

### Versioning

TBD


## Governance

This GitHub public repository (
**<https://github.com/oasis-open/cti-python-stix2>** ) was [proposed](https://lists.oasis-open.org/archives/cti/201702/msg00008.html)
and
[approved](https://www.oasis-open.org/committees/download.php/60009/)
\[[bis](https://issues.oasis-open.org/browse/TCADMIN-2549)\] by the [OASIS Cyber Threat Intelligence (CTI)
TC](https://www.oasis-open.org/committees/cti/) as an [OASIS Open
Repository](https://www.oasis-open.org/resources/open-repositories/) to
support development of open source resources related to Technical
Committee work.

While this Open Repository remains associated with the sponsor TC, its
development priorities, leadership, intellectual property terms,
participation rules, and other matters of governance are [separate and
distinct](https://github.com/oasis-open/cti-python-stix2/blob/master/CONTRIBUTING.md#governance-distinct-from-oasis-tc-process)
from the OASIS TC Process and related policies.

All contributions made to this Open Repository are subject to open
source license terms expressed in the [BSD-3-Clause
License](https://www.oasis-open.org/sites/www.oasis-open.org/files/BSD-3-Clause.txt).
That license was selected as the declared ["Applicable
License"](https://www.oasis-open.org/resources/open-repositories/licenses)
when the Open Repository was created.

As documented in ["Public Participation
Invited](https://github.com/oasis-open/cti-python-stix2/blob/master/CONTRIBUTING.md#public-participation-invited)",
contributions to this OASIS Open Repository are invited from all
parties, whether affiliated with OASIS or not. Participants must have a
GitHub account, but no fees or OASIS membership obligations are
required. Participation is expected to be consistent with the [OASIS
Open Repository Guidelines and
Procedures](https://www.oasis-open.org/policies-guidelines/open-repositories),
the open source
[LICENSE](https://github.com/oasis-open/cti-python-stix2/blob/master/LICENSE)
designated for this particular repository, and the requirement for an
[Individual Contributor License
Agreement](https://www.oasis-open.org/resources/open-repositories/cla/individual-cla)
that governs intellectual property.


### <a id="maintainers">Maintainers</a>

Open Repository
[Maintainers](https://www.oasis-open.org/resources/open-repositories/maintainers-guide)
are responsible for oversight of this project's community development
activities, including evaluation of GitHub [pull
requests](https://github.com/oasis-open/cti-python-stix2/blob/master/CONTRIBUTING.md#fork-and-pull-collaboration-model)
and
[preserving](https://www.oasis-open.org/policies-guidelines/open-repositories#repositoryManagement)
open source principles of openness and fairness. Maintainers are
recognized and trusted experts who serve to implement community goals
and consensus design preferences.

Initially, the associated TC members have designated one or more persons
to serve as Maintainer(s); subsequently, participating community members
may select additional or substitute Maintainers, per [consensus
agreements](https://www.oasis-open.org/resources/open-repositories/maintainers-guide#additionalMaintainers).

**<a id="currentMaintainers">Current Maintainers of this Open Repository</a>**

* [Greg Back](mailto:gback@mitre.org); GitHub ID: <https://github.com/gtback/>; WWW: [MITRE Corporation](http://www.mitre.org/)
* [Chris Lenk](mailto:clenk@mitre.org); GitHub ID:  <https://github.com/clenk/>; WWW: [MITRE Corporation](http://www.mitre.org/)

## <a id="aboutOpenRepos">About OASIS Open Repositories</a>

* [Open Repositories: Overview and Resources](https://www.oasis-open.org/resources/open-repositories/)
* [Frequently Asked Questions](https://www.oasis-open.org/resources/open-repositories/faq)
* [Open Source Licenses](https://www.oasis-open.org/resources/open-repositories/licenses)
* [Contributor License Agreements (CLAs)](https://www.oasis-open.org/resources/open-repositories/cla)
* [Maintainers' Guidelines and Agreement](https://www.oasis-open.org/resources/open-repositories/maintainers-guide)


## <a id="feedback">Feedback</a>

Questions or comments about this Open Repository's activities should be
composed as GitHub issues or comments. If use of an issue/comment is not
possible or appropriate, questions may be directed by email to the
Maintainer(s) [listed above](#currentMaintainers). Please send general
questions about Open Repository participation to OASIS Staff at
<repository-admin@oasis-open.org> and any specific CLA-related questions
to <repository-cla@oasis-open.org>.
