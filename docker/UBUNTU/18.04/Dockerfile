FROM python:2
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
RUN apt-get update \
    && apt-get install -y --no-install-recommends python-all python-all-dev libgnutls28-dev libboost-all-dev  \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /usr/src/TCGStorageAPI
COPY . .
RUN python setup.py opensea
RUN python setup.py build
RUN cp -r build/lib.linux-x86_64-2.7/TCGstorageAPI /usr/local/lib/python2.7/site-packages/.
