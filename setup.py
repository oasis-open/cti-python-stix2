#!/usr/bin/env python
from setuptools import find_packages, setup


def get_version():
    with open('stix2/version.py') as f:
        for line in f.readlines():
            if line.startswith("__version__"):
                version = line.split()[-1].strip('"')
                return version
        raise AttributeError("Package does not have a __version__")


install_requires = [
    'pytz',
    'six',
    'python-dateutil',
    'requests',
]

setup(
    name='stix2',
    description="Produce and consume STIX 2 JSON content",
    version=get_version(),
    packages=find_packages(),
    install_requires=install_requires,
    keywords="stix stix2 json cti cyber threat intelligence",
)
