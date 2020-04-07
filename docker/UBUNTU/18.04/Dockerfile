FROM python:3.6
COPY requirements.txt ./
RUN pip3 install --no-cache-dir -r requirements.txt
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3-all python3-all-dev libgnutls28-dev libboost-all-dev  \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /usr/src/TCGStorageAPI
COPY . .
RUN python3 setup.py opensea
RUN python3 setup.py build
RUN cp -r build/lib.linux-x86_64-3.6/TCGstorageAPI /usr/local/lib/python3.6/site-packages/.
