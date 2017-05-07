#!/usr/bin/env python2

from setuptools import setup, find_packages

setup(
    name='nsshell',
    version='0.9.0',
    packages=find_packages(),
    zip_safe=False,
    include_package_data=True,
    install_requires=[
        'twisted',
        'netaddr',
        'requests',
    ],
    classifiers=[
        'Brought to you by rook.'
    ],
    entry_points={
        'console_scripts': [
            'nsshell = nsshell:main',
        ]
    }
)
