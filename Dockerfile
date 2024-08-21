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
FROM ubuntu:22.04 AS tcgstorageapi

RUN apt-get update && apt-get install -y --reinstall ca-certificates

RUN DEBIAN_FRONTEND="noninteractive" apt-get -y install tzdata

WORKDIR /tcgstorageapi

COPY TCGstorageAPI /tcgstorageapi/TCGstorageAPI
COPY setup.py /tcgstorageapi/setup.py
COPY opensea-common /tcgstorageapi/opensea-common
COPY opensea-operations /tcgstorageapi/opensea-operations
COPY opensea-transport /tcgstorageapi/opensea-transport
COPY pysed /tcgstorageapi/pysed
COPY sed_cli /tcgstorageapi/sed_cli
COPY requirements.txt /tcgstorageapi/requirements.txt

RUN apt update -y && apt-get install -y python3-pip
RUN pip3 install --no-cache-dir -r requirements.txt
RUN apt-get install -y --no-install-recommends python3-all python3-all-dev libgnutls28-dev libboost-all-dev  \
    && rm -rf /var/lib/apt/lists/*
RUN python3 setup.py opensea
RUN python3 setup.py build
RUN cp -r build/lib.linux-x86_64-3.10/TCGstorageAPI /usr/local/lib/python3.10/dist-packages/.
