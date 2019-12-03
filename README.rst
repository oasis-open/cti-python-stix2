|Build_Status| |Coverage| |Version| |Downloads_Badge| |Documentation_Status|

cti-python-stix2
================

This is an `OASIS TC Open Repository <https://www.oasis-open.org/resources/open-repositories/>`__.
See the `Governance <#governance>`__ section for more information.

This repository provides Python APIs for serializing and de-serializing STIX2
JSON content, along with higher-level APIs for common tasks, including data
markings, versioning, and for resolving STIX IDs across multiple data sources.

For more information, see `the documentation <https://stix2.readthedocs.io/>`__ on ReadTheDocs.

Installation
------------

Install with `pip <https://pip.pypa.io/en/stable/>`__:

.. code-block:: bash

  $ pip install stix2

Usage
-----

To create a STIX object, provide keyword arguments to the type's constructor.
Certain required attributes of all objects, such as ``type`` or ``id``,  will
be set automatically if not provided as keyword arguments.

.. code-block:: python

    from stix2 import Indicator

    indicator = Indicator(name="File hash for malware variant",
                          labels=["malicious-activity"],
                          pattern="[file:hashes.md5 = 'd41d8cd98f00b204e9800998ecf8427e']")

To parse a STIX JSON string into a Python STIX object, use ``parse()``:

.. code-block:: python

    from stix2 import parse

    indicator = parse("""{
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--dbcbd659-c927-4f9a-994f-0a2632274394",
        "created": "2017-09-26T23:33:39.829Z",
        "modified": "2017-09-26T23:33:39.829Z",
        "name": "File hash for malware variant",
        "indicator_types": [
            "malicious-activity"
        ],
        "pattern_type": "stix",
        "pattern": "[file:hashes.md5 ='d41d8cd98f00b204e9800998ecf8427e']",
        "valid_from": "2017-09-26T23:33:39.829952Z"
    }""")

    print(indicator)

For more in-depth documentation, please see `https://stix2.readthedocs.io/ <https://stix2.readthedocs.io/>`__.

STIX 2.X Technical Specification Support
----------------------------------------

This version of python-stix2 brings initial support to STIX 2.1 currently at the
CSD level. The intention is to help debug components of the library and also
check for problems that should be fixed in the specification.

The `stix2` Python library is built to support multiple versions of the STIX
Technical Specification. With every major release of stix2 the ``import stix2``
statement will automatically load the SDO/SROs equivalent to the most recent
supported 2.X Committee Specification. Please see the library documentation for
more details.

Governance
----------

This GitHub public repository (**https://github.com/oasis-open/cti-python-stix2**) was
`proposed <https://lists.oasis-open.org/archives/cti/201702/msg00008.html>`__ and
`approved <https://www.oasis-open.org/committees/download.php/60009/>`__
[`bis <https://issues.oasis-open.org/browse/TCADMIN-2549>`__] by the
`OASIS Cyber Threat Intelligence (CTI) TC <https://www.oasis-open.org/committees/cti/>`__
as an `OASIS TC Open Repository <https://www.oasis-open.org/resources/open-repositories/>`__
to support development of open source resources related to Technical Committee work.

While this TC Open Repository remains associated with the sponsor TC, its
development priorities, leadership, intellectual property terms, participation
rules, and other matters of governance are `separate and distinct
<https://github.com/oasis-open/cti-python-stix2/blob/master/CONTRIBUTING.md#governance-distinct-from-oasis-tc-process>`__
from the OASIS TC Process and related policies.

All contributions made to this TC Open Repository are subject to open
source license terms expressed in the `BSD-3-Clause License <https://www.oasis-open.org/sites/www.oasis-open.org/files/BSD-3-Clause.txt>`__.
That license was selected as the declared `"Applicable License" <https://www.oasis-open.org/resources/open-repositories/licenses>`__
when the TC Open Repository was created.

As documented in `"Public Participation Invited
<https://github.com/oasis-open/cti-python-stix2/blob/master/CONTRIBUTING.md#public-participation-invited>`__",
contributions to this OASIS TC Open Repository are invited from all parties,
whether affiliated with OASIS or not. Participants must have a GitHub account,
but no fees or OASIS membership obligations are required. Participation is
expected to be consistent with the `OASIS TC Open Repository Guidelines and Procedures
<https://www.oasis-open.org/policies-guidelines/open-repositories>`__,
the open source `LICENSE <https://github.com/oasis-open/cti-python-stix2/blob/master/LICENSE>`__
designated for this particular repository, and the requirement for an
`Individual Contributor License Agreement <https://www.oasis-open.org/resources/open-repositories/cla/individual-cla>`__
that governs intellectual property.

Maintainers
~~~~~~~~~~~

TC Open Repository `Maintainers <https://www.oasis-open.org/resources/open-repositories/maintainers-guide>`__
are responsible for oversight of this project's community development
activities, including evaluation of GitHub
`pull requests <https://github.com/oasis-open/cti-python-stix2/blob/master/CONTRIBUTING.md#fork-and-pull-collaboration-model>`__
and `preserving <https://www.oasis-open.org/policies-guidelines/open-repositories#repositoryManagement>`__
open source principles of openness and fairness. Maintainers are recognized
and trusted experts who serve to implement community goals and consensus design
preferences.

Initially, the associated TC members have designated one or more persons to
serve as Maintainer(s); subsequently, participating community members may
select additional or substitute Maintainers, per `consensus agreements
<https://www.oasis-open.org/resources/open-repositories/maintainers-guide#additionalMaintainers>`__.

.. _currentmaintainers:

**Current Maintainers of this TC Open Repository**

-  `Chris Lenk <mailto:clenk@mitre.org>`__; GitHub ID:
   https://github.com/clenk/; WWW: `MITRE Corporation <http://www.mitre.org/>`__

-  `Emmanuelle Vargas-Gonzalez <mailto:emmanuelle@mitre.org>`__; GitHub ID:
   https://github.com/emmanvg/; WWW: `MITRE
   Corporation <https://www.mitre.org/>`__

-  `Jason Keirstead <mailto:Jason.Keirstead@ca.ibm.com>`__; GitHub ID:
   https://github.com/JasonKeirstead; WWW: `IBM <http://www.ibm.com/>`__

About OASIS TC Open Repositories
--------------------------------

-  `TC Open Repositories: Overview and Resources <https://www.oasis-open.org/resources/open-repositories/>`__
-  `Frequently Asked Questions <https://www.oasis-open.org/resources/open-repositories/faq>`__
-  `Open Source Licenses <https://www.oasis-open.org/resources/open-repositories/licenses>`__
-  `Contributor License Agreements (CLAs) <https://www.oasis-open.org/resources/open-repositories/cla>`__
-  `Maintainers' Guidelines and Agreement <https://www.oasis-open.org/resources/open-repositories/maintainers-guide>`__

Feedback
--------

Questions or comments about this TC Open Repository's activities should be
composed as GitHub issues or comments. If use of an issue/comment is not
possible or appropriate, questions may be directed by email to the
Maintainer(s) `listed above <#currentmaintainers>`__. Please send general
questions about TC Open Repository participation to OASIS Staff at
repository-admin@oasis-open.org and any specific CLA-related questions
to repository-cla@oasis-open.org.

.. |Build_Status| image:: https://travis-ci.org/oasis-open/cti-python-stix2.svg?branch=master
   :target: https://travis-ci.org/oasis-open/cti-python-stix2
   :alt: Build Status
.. |Coverage| image:: https://codecov.io/gh/oasis-open/cti-python-stix2/branch/master/graph/badge.svg
   :target: https://codecov.io/gh/oasis-open/cti-python-stix2
   :alt: Coverage
.. |Version| image:: https://img.shields.io/pypi/v/stix2.svg?maxAge=3600
   :target: https://pypi.python.org/pypi/stix2/
   :alt: Version
.. |Downloads_Badge| image:: https://img.shields.io/pypi/dm/stix2.svg?maxAge=3600
   :target: https://pypi.python.org/pypi/stix2/
   :alt: Downloads
.. |Documentation_Status| image:: https://readthedocs.org/projects/stix2/badge/?version=latest
   :target: https://stix2.readthedocs.io/en/latest/?badge=latest
   :alt: Documentation Status
