# TCGstorageAPI

## API for TCG Storage operations on SATA and SAS Self-Encrypting Drives

##### Copyright (c) 2020 Seagate Technology LLC and/or its Affiliates, All Rights Reserved

BINARIES and SOURCE CODE files of the TCGstorageAPI open source project are made available under the [Apache License 2.0](https://opensource.org/licenses/Apache-2.0).  

It uses the openSeaChest project, its repository is maintained at https://github.com/Seagate/openSeaChest.

TCGstorageAPI implements the TCG Storage Enterprise SSC and Opal SSC protocols for configuring SEDs. It supports a number of operations, such as taking ownership of the drive, setting authentication credentials, configuring bands (TCG Ranges), locking and unlocking of bands, etc. The API should be used in combination with Key Manager to securely store drive authentication credentials.  

### Required libraries

This API depends on the below libraries for transport of TCG payloads to and from the device.

**opensea-common**      - Operating System common operations, not specific to
                      storage standards. Contains functions and defines that
                      are useful to all other libraries.

**opensea-transport**   - Contains standard ATA/SCSI/NVMe functions based on open
                      standards for these command sets.  This layer also
                      supports different transporting these commands through
                      operating systems to the storage devices. Code depends on
                      opensea-common.

**opensea-operations**  - Contains common use cases for operations to be performed
                      on a storage device. This layer encapsulates the nuances
                      of each command set (ATA/SCSI) and operating systems
                      (Linux/Windows etc.) Depends on opensea-common and
                      opensea-transport.

### Source code access

Depending on your git version & client you can use either of the following commands to clone the repository.

`git clone --recurse-submodules https://github.com/Seagate/TCGstorageAPI.git`

or

`git clone --recursive https://github.com/Seagate/TCGstorageAPI.git`

Note that cloning **_recursively_** is **_important_** as it clones all the necessary submodules.

### Download packages

#### Linux

##### CentOS 7

Start by updating the package index:

`sudo yum update`

Install python3:

`sudo yum install python3`

Install gcc and g++:

`sudo yum -y install gcc`

`sudo yum -y install gcc-c++`

Install boost:

`sudo yum install epel-release`

`sudo yum install boost-python36-devel.x86_64`

Install gnutls:

`sudo yum -y install gnutls-devel`

Install python3-extensions:

`sudo yum -y install python3-devel`

Install rpm build package
 
 `sudo yum install rpm-build`

Change directory to tcgstorageapi and download the package dependencies:

 `pip3 install -r requirements.txt`
 
##### Ubuntu 18.04

Start by updating package index

`sudo apt-get update`

Install python3 and pip:

`sudo apt install python3`

`sudo apt install python3-pip`

Install python extensions:

`sudo apt-get install -y --no-install-recommends python3-all python3-all-dev`

Install gnutls:

`sudo apt-get install libgnutls28-dev`

Install Boost-Python:

`sudo apt-get install libboost-all-dev`

Change directory to tcgstorageapi and download the package dependencies:

`pip3 install --no-cache-dir -r requirements.txt`

### Building

#### Linux

##### CentOS 7

From the terminal, change directory to tcgstorageapi. 

Run the command "python3 setup.py opensea" to build the openseachest libraries. After the command completes, run "python3 setup.py bdist_rpm" to build an rpm distro. 

##### Ubuntu 18.04

From the terminal, change directory to tcgstorageapi.

Run the command "python3 setup.py opensea" to build the openseachest libraries. After the command completes, run "python3 setup.py build" to build the library.

### Installation

#### Centos 7

From the tcgstorageapi directory, run "yum install -y  dist/TCGstorageAPI-*.x86_64.rpm" to install the built python3 package.

#### Ubuntu 18.04

Change directory to build/lib.linux-x86_64-3.6. Copy TCGstorageAPI directory to /usr/local/lib/python3/dist-packages/.

On linux systems, to allow the security commands to reach the SATA drives, set the below flag value to 1:

/sys/module/libata/parameters/allow_tpm

**Alternatively, the package can be built and installed using the Dockerfile**.

### Docker for CentOS

To build the docker image from a Dockerfile, from the tcgstorageapi directory run the command as root "sudo docker build -f docker/(OS flavor)/(OS version)/docker-file-name -t docker-image-name ."

Example: sudo docker build -f docker/CENTOS/7/Dockerfile -t tcgstorageapi-centos .

The docker container needs to be run in the privileged mode since you are accessing the device. To run the docker container, run the following command "sudo docker run -it --privileged docker-image-name /bin/bash". A new bash shell should appear indicating the running container, you can run the sedcfg.py script from the bash.

Example: sudo docker run -it --privileged tcgstorageapi-centos /bin/bash

### Example
Look in the samples directory and run the script sample_cli.py.

WARNING: the credentials for the Admin and Users are hardcoded in the example and should be changed!

The API can support key managers.

The example currently works with 2 bands (TCG Ranges).

The example script must be run as Administrator/root.
