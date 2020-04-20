#----------------------------------------------------------------------------
# Do NOT modify or remove this copyright
#
# Copyright (c) 2020 Seagate Technology LLC and/or its Affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
#****************************************************************************
#
# \file setup.py
#
#-----------------------------------------------------------------------------
#!/usr/bin/env python
# Setuptools script to build TCGstorageAPI
# TCGstorageAPI requires building the pysed C++ dynamic link library pysed.so
# Pysed requires the OpenSea Libraries: opensea-transport, opensea-common, and opensea-operations.
# Build the static libraries for opensea before building pysed.
#
# To use the tool run python setup.py with the following argument options
#
# To build the Opensea libraries:
#    python3 setup.py opensea
#
# To build the pysed dynamic library:
#    python3 setup.py build
#
# To build a TCGstorageAPI linux rpm:
#    python3 setup.py bdist_rpm
#
#
from setuptools import setup, Extension
import subprocess
import sys

from setuptools import Command

class BuildOpenSea(Command):
    user_options = []

    def initialize_options(self):
        """Abstract method that is required to be overwritten"""

    def finalize_options(self):
        """Abstract method that is required to be overwritten"""
    def run(self):
        print(" => Building OpenSea Static Libraries ...")
        subprocess.call(['gmake', '-C', 'opensea-transport/Make/gcc'])
        subprocess.call(['gmake', '-C', 'opensea-operations/Make/gcc'])
        subprocess.call(['gmake', '-C', 'opensea-common/Make/gcc'])

pysed = Extension('TCGstorageAPI.pysed', [
        'pysed/pysed.cpp',
        'pysed/TcgDrive.cpp',
        'pysed/transport.cpp',
        'pysed/TcgScanner.cpp',
        'pysed/parser.tab.cpp',
        'pysed/support.cpp',
        'pysed/Tls.cpp',
    ],
    libraries=['boost_python3', 'gnutls', 'gnutlsxx' ],
    include_dirs = ['pysed','opensea-transport/include','opensea-common/include','opensea-operations/include','opensea-transport/include/vendor','/usr/local/include'],
    extra_objects=['opensea-transport/Make/gcc/lib/libopensea-transport.a','opensea-common/Make/gcc/lib/libopensea-common.a','opensea-operations/Make/gcc/lib/libopensea-operations.a'],
    extra_compile_args=['-O0','-g','-DDISABLE_NVME_PASSTHROUGH']
)

if sys.platform == 'freebsd12':
    pysed.libraries=[lib.replace('boost_python3', 'boost_python37') for lib in pysed.libraries] 
    pysed.libraries.append('cam')

setup(
    name='TCGstorageAPI',
    description='API implementing TCG storage specifications for SED',
    long_description='API implementing TCG storage specifications for SED.\nProvides support for taking ownership of the drive, configuring bands, locking and unlocking. Includes support for SAS, SATA interfaces via OpenSea-libraries,\nSED support for Enterprise(Full), OpalV2(Limited)',
    version='1.0',
    packages=['TCGstorageAPI'],
    ext_modules=[pysed],
    cmdclass={
        'opensea': BuildOpenSea,
    }
)
