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
FROM python:3.6
COPY requirements.txt ./
RUN pip3 install --no-cache-dir -r requirements.txt
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3-all python3-all-dev libgnutls28-dev libboost-all-dev  \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /usr/src/TCGStorageAPI
COPY . .
RUN ln -s /usr/bin/make /usr/bin/gmake
RUN python3 setup.py opensea
RUN python3 setup.py build
RUN cp -r build/lib.linux-x86_64-3.6/TCGstorageAPI /usr/local/lib/python3.6/site-packages/.
