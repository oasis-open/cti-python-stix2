#!/usr/bin/env python
from codecs import open
import os.path

from setuptools import find_packages, setup

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
VERSION_FILE = os.path.join(BASE_DIR, 'stix2', 'version.py')


def get_version():
    with open(VERSION_FILE) as f:
        for line in f.readlines():
            if line.startswith('__version__'):
                version = line.split()[-1].strip('"')
                return version
        raise AttributeError("Package does not have a __version__")


def get_long_description():
    with open('README.rst') as f:
        return f.read()


setup(
    name='stix2',
    version=get_version(),
    description='Produce and consume STIX 2 JSON content',
    long_description=get_long_description(),
    long_description_content_type='text/x-rst',
    url='https://oasis-open.github.io/cti-documentation/',
    author='OASIS Cyber Threat Intelligence Technical Committee',
    author_email='cti-users@lists.oasis-open.org',
    maintainer='Chris Lenk',
    maintainer_email='clenk@mitre.org',
    license='BSD',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Topic :: Security',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
    ],
    keywords='stix stix2 json cti cyber threat intelligence',
    packages=find_packages(exclude=['*.test', '*.test.*']),
    python_requires='>=3.6',
    install_requires=[
        'pytz',
        'requests',
        'simplejson',
        'stix2-patterns>=1.2.0',
    ],
    project_urls={
        'Documentation': 'https://stix2.readthedocs.io/',
        'Source Code': 'https://github.com/oasis-open/cti-python-stix2/',
        'Bug Tracker': 'https://github.com/oasis-open/cti-python-stix2/issues/',
    },
    extras_require={
        'taxii': ['taxii2-client>=2.3.0'],
        'semantic': ['haversine', 'rapidfuzz'],
    },
)
