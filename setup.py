#!/usr/bin/env python
from setuptools import setup, find_packages

install_requires = [
    'pytz',
]

setup(
    name='stix2',
    description="Produce and consume STIX 2 JSON content",
    version='0.0.1',
    packages=find_packages(),
    install_requires=install_requires,
    keywords="stix stix2 json cti cyber threat intelligence",
)
