Contributing
============

We're thrilled that you're interested in contributing to python-stix2! Here are
some things you should know:

- `contribution-guide.org <http://www.contribution-guide.org/>`_ has great ideas
  for contributing to any open-source project (not just python-stix2).
- All contributors must sign a Contributor License Agreement. See
  `CONTRIBUTING.md <https://github.com/oasis-open/cti-python-stix2/blob/master/CONTRIBUTING.md>`_
  in the project repository for specifics.
- If you are planning to implement a major feature (vs. fixing a bug), please
  discuss with a project maintainer first to ensure you aren't duplicating the
  work of someone else, and that the feature is likely to be accepted.

Now, let's get started!

Setting up a development environment
------------------------------------

We recommend using a `virtualenv <https://virtualenv.pypa.io/en/stable/>`_.

1. Clone the repository. If you're planning to make pull request, you should fork
the repository on GitHub and clone your fork instead of the main repo:

.. prompt:: bash

    git clone https://github.com/yourusername/cti-python-stix2.git

2. Install develoment-related dependencies:

.. prompt:: bash

    cd cti-python-stix2
    pip install -r requirements.txt

3. Install `pre-commit <http://pre-commit.com/#usage>`_ git hooks:

.. prompt:: bash

    pre-commit install

At this point you should be able to make changes to the code.

Code style
----------

All code should follow `PEP 8 <https://www.python.org/dev/peps/pep-0008/>`_. We
allow for line lengths up to 160 characters, but any lines over 80 characters
should be the exception rather than the rule. PEP 8 conformance will be tested
automatically by Tox and Travis-CI (see below).

Testing
-------

.. note::

    All of the tools mentioned in this section are installed when you run ``pip
    install -r requirements.txt``.

python-stix2 uses `pytest <http://pytest.org>`_ for testing.  We encourage the
use of test-driven development (TDD), where you write (failing) tests that
demonstrate a bug or proposed new feature before writing code that fixes the bug
or implements the features. Any code contributions to python-stix2 should come
with new or updated tests.

To run the tests in your current Python environment, use the ``pytest`` command
from the root project directory:

.. prompt:: bash

    pytest

This should show all of the tests that ran, along with their status.

You can run a specific test file by passing it on the command line:

.. prompt:: bash

    pytest stix2/test/test_<xxx>.py

To ensure that the test you wrote is running, you can deliberately add an
``assert False`` statement at the beginning of the test. This is another benefit
of TDD, since you should be able to see the test failing (and ensure it's being
run) before making it pass.

`tox <https://tox.readthedocs.io/en/latest/>`_ allows you to test a package
across multiple versions of Python. Setting up multiple Python environments is
beyond the scope of this guide, but feel free to ask for help setting them up.
Tox should be run from the root directory of the project:

.. prompt:: bash

    tox

We aim for high test coverage, using the `coverage.py
<http://coverage.readthedocs.io/en/latest/>`_ library. Though it's not an
absolute requirement to maintain 100% coverage, all code contributions must
be accompanied by tests. To run coverage and look for untested lines of code,
run:

.. prompt:: bash

    pytest --cov=stix2
    coverage html

then look at the resulting report in ``htmlcov/index.html``.

All commits pushed to the ``master`` branch or submitted as a pull request are
tested with `Travis-CI <https://travis-ci.org/oasis-open/cti-python-stix2>`_
automatically.
