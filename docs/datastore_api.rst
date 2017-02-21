.. _datastore_api:

DataStore API
=============

.. warning::

    The DataStore API is still in the planning stages and may be subject to
    major changes. We encourage anyone with feedback to contact the maintainers
    to help ensure the API meets a large variety of use cases.

One prominent feature of python-stix2 will be an interface for connecting
different backend data stores containing STIX content. This will allow a uniform
interface for querying and saving STIX content, and allow higher level code to
be written without regard to the underlying data storage format. python-stix2
will define the API and contain some default implementations of this API, but
developers are encouraged to write their own implementations.

Potential functions of the API include:

* get a STIX Object by ID (returns the most recent version).
* get all versions of a STIX object by ID.
* get all relationships involving a given object, and all related objects.
* save an object.
* query for objects that match certain criteria (query syntax TBD).

For all queries, the API will include a "filter" interface that can be used to
either explicitly include or exclude results with certain criteria. For example,

* only trust content from a set of object creators.
* exclude content from certain (untrusted) object creators.
* only include content with a confidence above a certain threshold (once
  confidence is added to STIX).
* only return content that can be shared with external parties (in other words,
  that has TLP:GREEN markings).

Additionally, the python-stix2 library will contain a "composite" data store,
which implements the DataStore API while delegating functionality to one or more
"child" data stores.
