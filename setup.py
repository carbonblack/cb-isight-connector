#!/usr/bin/env python

import os
import sys

sys.path.insert(0, "src/")

from cbisight.bridge import __version__
from distutils.core import setup


def get_data_files(rootdir):
    # automatically build list of (dir, [file1, file2, ...],)
    # for all files under src/root/ (or provided rootdir)
    results = []
    for root, dirs, files in os.walk(rootdir):
        if len(files) > 0:
            dirname = os.path.relpath(root, rootdir)
            flist = [os.path.join(root, f) for f in files]
            results.append(("/%s" % dirname, flist))
    return results

data_files = get_data_files("src/root")

setup(
    name='python-cbisight-connector',
    version=__version__,
    url='http://www.bit9.com/',
    license='MIT',
    author='Carbon Black',
    author_email='support@bit9.com',
    description='Carbon Black iSIGHT Connector',
    long_description=__doc__,
    packages=['cbisight'],
    data_files=data_files,
    package_dir = {'cbisight': 'src/cbisight'},
    package_data={'cbisight': ['content/*']},
    options={'bdist_rpm': {'post_install': 'post_install', 'pre_uninstall': 'pre_uninstall'}},
    platforms='any',
    classifiers=[
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: MIT',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ]
)
