Overview
========

High level goals/principles of the python-stix2 library:

1. It should be as easy as possible (but no easier!) to perform common tasks of
   producing, consuming, and processing STIX 2 content.
2. It should be hard, if not impossible, to emit invalid STIX 2.
3. The library should default to doing "the right thing", complying with both
   the STIX 2.0 spec, as well as associated best practices. The library should
   make it hard to do "the wrong thing".

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
