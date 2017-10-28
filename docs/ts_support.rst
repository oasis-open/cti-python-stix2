How imports will work
---------------------

Imports can be used in different ways depending on the use case and support
levels.

People who want to (in general) support the latest version of STIX 2.X without
making changes, implicitly using the latest version

.. code:: python

    import stix2
    ...
    stix2.Indicator(...)

or

.. code:: python

    from stix2 import Indicator
    ...
    Indicator(...)

People who want to use an explicit version

.. code:: python

    import stix2.v20
    ...
    stix2.v20.Indicator(...)

or

.. code:: python

    from stix2.v20 import Indicator
    ...
    Indicator(...)

or even,

.. code:: python

    import stix2.v20 as stix2
    ...
    stix2.Indicator(...)

The last option makes it easy to update to a new version in one place per file,
once you've made the deliberate action to do this.

People who want to use multiple versions in a single file:

.. code:: python

    import stix2
    ...
    stix2.v20.Indicator(...)
    ...
    stix2.v21.Indicator(...)

or

.. code:: python

    from stix2 import v20, v21
    ...
    v20.Indicator(...)
    ...
    v21.Indicator(...)

or (less preferred):

.. code:: python

    from stix2.v20 import Indicator as Indicator_v20
    from stix2.v21 import Indicator as Indicator_v21
    ...
    Indicator_v20(...)
    ...
    Indicator_v21(...)

How parsing will work
---------------------

If the ``version`` positional argument is not provided. The data will be parsed
using the latest version of STIX 2.X supported by the `stix2` library.

You can lock your `parse()` method to a specific STIX version by

.. code:: python

    from stix2 import parse

    indicator = parse("""{
        "type": "indicator",
        "id": "indicator--dbcbd659-c927-4f9a-994f-0a2632274394",
        "created": "2017-09-26T23:33:39.829Z",
        "modified": "2017-09-26T23:33:39.829Z",
        "labels": [
            "malicious-activity"
        ],
        "name": "File hash for malware variant",
        "pattern": "[file:hashes.md5 = 'd41d8cd98f00b204e9800998ecf8427e']",
        "valid_from": "2017-09-26T23:33:39.829952Z"
    }""", version="2.0")
    print(indicator)

Keep in mind that if a 2.1 or higher object is parsed, the operation will fail.

How will custom work
--------------------

CustomObjects, CustomObservable, CustomMarking and CustomExtensions must be
registered explicitly by STIX version. This is a design decision since properties
or requirements may change as the STIX Technical Specification advances.

You can perform this by,

.. code:: python

    import stix2

    # Make my custom observable available in STIX 2.0
    @stix2.v20.observables.CustomObservable('x-new-object-type',
                                        (("prop", stix2.properties.BooleanProperty())))
    class NewObject2(object):
        pass


    # Make my custom observable available in STIX 2.1
    @stix2.v21.observables.CustomObservable('x-new-object-type',
                                        (("prop", stix2.properties.BooleanProperty())))
    class NewObject2(object):
        pass
