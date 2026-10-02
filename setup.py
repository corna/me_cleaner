#!/usr/bin/python

from setuptools import setup

setup(
    name="me_cleaner",
    version="1.2",
    description="Tool for partial deblobbing of Intel ME/TXE firmware images",
    url="https://github.com/corna/me_cleaner",
    author="Nicola Corna",
    author_email="nicola@corna.info",
    license="GPLv3+",
    scripts=['me_cleaner.py'],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
    ]
)

