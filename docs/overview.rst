Overview
========

Goals
-----

High level goals/principles of the python-stix2 library:

1. It should be as easy as possible (but no easier!) to perform common tasks of
   producing, consuming, and processing STIX 2 content.
2. It should be hard, if not impossible, to emit invalid STIX 2.
3. The library should default to doing "the right thing", complying with both
   the STIX 2.0 spec, as well as associated best practices. The library should
   make it hard to do "the wrong thing".

Design Decisions
----------------

To accomplish these goals, and to incorporate lessons learned while developing
python-stix (for STIX 1.x), several decisions influenced the design of
python-stix2:

1. All data structures are immutable by default. In contrast to python-stix,
   where users would create an object and then assign attributes to it, in
   python-stix2 all properties must be provided when creating the object.
2. Where necessary, library objects should act like ``dict``'s. When treated as
   a ``str``, the JSON reprentation of the object should be used.
3. Core Python data types (including numeric types, ``datetime``) should be used
   when appropriate, and serialized to the correct format in JSON as specified
   in the STIX 2.0 spec.

Architecture
------------

The `stix2` library APIs are divided into three logical layers, representing
different levels of abstraction useful in different types of scripts and larger
applications. It is possible to combine multiple layers in the same program,
and the higher levels build on the layers below.


Object Layer
^^^^^^^^^^^^

The lowest layer, **Object Layer**, is where Python objects representing STIX 2
data types (such as SDOs, SROs, and Cyber Observable Objects, as well as
non-top-level objects like External References, Kill Chain phases, and Cyber
Observable extensions) are created, and can be serialized and deserialized
to and from JSON representation.

This layer is appropriate for stand-alone scripts that produce or consume STIX
2 content, or can serve as a low-level data API for larger applications that
need to represent STIX objects as Python classes.

At this level, non-embedded reference properties (those ending in ``_ref``, such
as the links from a Relationship object to its source and target objects) are
not implemented as references between the Python objects themselves, but by
simply having the same values in ``id`` and reference properties. There is no
referential integrity maintained by the ``stix2`` library.

*This layer is mostly complete.*

Environment Layer
^^^^^^^^^^^^^^^^^

The **Environment Layer** adds several components that make it easier to handle
STIX 2 data as part of a larger application and as part of a larger cyber threat
intelligence ecosystem.

- ``Data Source``\s represent locations from which STIX data can be retrieved,
  such as a TAXII server, database, or local filesystem. The Data Source API
  abstracts differences between these storage location, giving a common API to
  get objects by ID or query by various properties, as well as allowing
  federated operations over multiple data sources.
- Similarly, ``Data Sink`` objects represent destinations for sending STIX data.
- An ``Object Factory`` provides a way to add common properties to all created
  objects (such as the same ``created_by_ref``, or a ``StatementMarking`` with
  copyright information or terms of use for the STIX data).

Each of these components can be used individually, or combined as part of an
``Environment``. These ``Environment`` objects allow different settings to be
used by different users of a multi-user application (such as a web application).

*This layer is mostly complete.*

Workbench Layer
^^^^^^^^^^^^^^^

The highest layer of the ``stix2`` APIs is the **Workbench Layer**, designed for
a single user in a highly-interactive analytical environment (such as a `Jupyter
Notebook <https://jupyter.org/>`_). It builds on the lower layers of the API,
while hiding most of their complexity. Unlike the other layers, this layer is
designed to be used directly by end users. For users who are comfortable with,
Python, the Workbench Layer makes it easy to quickly interact with STIX data
from a variety of sources without needing to write and run one-off Python
scripts.

*This layer is currently being developed.*
