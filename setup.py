#!/usr/bin/env python
from setuptools import find_packages, setup

install_requires = [
    'pytz',
    'six',
    'python-dateutil',
    'requests',
]

setup(
    name='stix2',
    description="Produce and consume STIX 2 JSON content",
    version='0.2.0',
    packages=find_packages(),
    install_requires=install_requires,
    keywords="stix stix2 json cti cyber threat intelligence",
)
