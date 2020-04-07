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
FROM centos:7
USER root
COPY requirements.txt ./
RUN yum -y update && \
yum -y install epel-release && \
yum -y install python3 boost-python36.x86_64 boost-python36-devel.x86_64 gcc gcc-c++ gnutls-devel rpm-build python3-devel && \
yum clean all
RUN pip3 install --no-cache-dir -r requirements.txt
WORKDIR /usr/src/TCGStorageAPI
COPY . .
RUN python3 setup.py opensea
RUN python3 setup.py bdist_rpm
RUN yum install -y  dist/TCGstorageAPI-*.x86_64.rpm
