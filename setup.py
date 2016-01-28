#!/usr/bin/env python
# coding:utf-8

from __future__ import print_function
from setuptools import setup, find_packages
import os

long_description = 'Visualizing a confusion matrix with gradations'

if os.path.exists('README_pypi.md'):
    try:
        import pypandoc
        read_md = lambda f: pypandoc.convert(f, 'rst')
        long_description = read_md('README_pypi.md')

    except ImportError:
        print("warning: pypandoc module not found, could not convert Markdown to RST")
        read_md = lambda f: open(f, 'r').read()
        long_description = read_md('README_pypi.md')


classifiers = [
   "Development Status :: 1 - Planning",
   "License :: OSI Approved :: MIT License",
   "Programming Language :: Python",
   "Topic :: Software Development",
]

setup(
    name="ipymessenger",
    version="0.0.5",
    description="ip messenger library fro python",
    url="https://github.com/denzow/ipymessenger",
    license="MIT",
    packages=["ipymessenger"],
    keywords="ipmessenger",
    long_description=long_description,
    classifiers=classifiers,
    author="denzow",
    author_email="denzow@example.com"
)