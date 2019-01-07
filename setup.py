#!/usr/bin/env python

import setuptools
import sys


requirements = ['psutil', 'distro']
if sys.version_info[:2] < (2, 7):
    requirements.append('argparse')


test_requirements = ['mock', 'nose']
if sys.version_info[:2] < (2, 7):
    test_requirements.extend(['flake8 < 3', 'unittest2'])
else:
    test_requirements.append('flake8')


setuptools.setup(
    name='ae-profile',
    version='0.1.0',
    url='https://github.com/oldarmyc/ae_preflight.git',
    license='Apache License, Version 2.0',
    author='Dave Kludt',
    author_email='dkludt@anaconda.com',
    description=(
        'Library to run preflight checks before installing Anaconda Enterprise'
    ),
    zip_safe=False,
    platforms='any',
    install_requires=requirements,
    extras_require={
        'tests': test_requirements
    },
    entry_points={
        'console_scripts': [
            'ae-profile=system_profile.profile:main'
        ]
    },
    packages=['system_profile'],
    classifiers=[
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: OS Independent',
        'Programming Language :: Python'
    ]
)
