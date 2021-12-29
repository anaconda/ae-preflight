#!/usr/bin/env python

import setuptools

requirements = ['psutil', 'distro']
test_requirements = ['mock', 'nose', 'flake8']

setuptools.setup(
    name='ae_preflight',
    version='0.1.9',
    url='https://github.com/Anaconda-Platform/ae-preflight',
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
            'ae-preflight=ae_preflight.profile:main'
        ]
    },
    packages=['ae_preflight'],
    classifiers=[
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: OS Independent',
        'Programming Language :: Python'
    ]
)
