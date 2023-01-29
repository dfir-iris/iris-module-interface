#!/usr/bin/env python3
#
#  IRIS Source Code
#  Copyright (C) 2021 - Airbus CyberSecurity (SAS)
#  ir@cyberactionlab.net
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU Lesser General Public
#  License as published by the Free Software Foundation; either
#  version 3 of the License, or (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#  Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public License
#  along with this program; if not, write to the Free Software Foundation,
#  Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
import pathlib

import setuptools

# The directory containing this file
CURR_DIR = pathlib.Path(__file__).parent

# The text of the README file
README = (CURR_DIR / "README.md").read_text()

setuptools.setup(
     name='iris_interface',
     version='1.2.0',
     packages=['iris_interface'],
     author="DFIR-IRIS - Airbus CyberSecurity",
     author_email="contact@dfir-iris.org",
     description="An interface for Iris modules",
     long_description=README,
     long_description_content_type="text/markdown",
     url="https://github.com/dfir-iris/iris-module-interface",
     classifiers=[
         "Programming Language :: Python :: 3",
         "License :: OSI Approved :: LGLP 3.0 License",
         "Operating System :: OS Independent",
     ],
 )