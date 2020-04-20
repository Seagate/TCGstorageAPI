[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
# TCGstorageAPI

## API for TCG Storage operations on SAS and SATA Self-Encrypting Drives

##### Copyright (c) 2020 Seagate Technology LLC and/or its Affiliates, All Rights Reserved

![](https://github.com/Seagate/TCGstorageAPI/workflows/TCGstorageAPI%20build/badge.svg?branch=Python2.7)

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

CentOS 7 comes with a pre-installed version of Python2.7, otherwise, install python.

Install gcc and g++:

`sudo yum -y install gcc`

`sudo yum -y install gcc-c++`

Install boost:

`sudo yum -y install boost-python`

`sudo yum -y install boost-devel`

Install gnutls:

`sudo yum -y install gnutls-devel`

Install Python-extensions:

`sudo yum -y install python-devel`

Download and install pip:

`curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py`

`python get-pip.py`

Download the python dependencies:

`pip install -r requirements.txt`

Install rpm build package:
 
 `sudo yum install rpm-build`

##### Ubuntu 18.04

Start by updating package index

`sudo apt-get update`

Install python2.7 and pip:

`sudo apt install python2.7-minimal`

`sudo apt-get install python-pip`

Install python extensions:

`sudo apt-get install -y --no-install-recommends python-all python-all-dev`

Install gnutls:

`sudo apt-get install libgnutls28-dev` 
 
 Install Boost-Python:
 
 `sudo apt-get install libboost-all-dev`
 
 Install Python setup tools:
 
 `sudo apt-get install python-setuptools`
 
Change directory to tcgstorageapi and download the package dependencies:

`pip install --no-cache-dir -r requirements.txt`

#### Windows 10

Your system will require the latest [Microsoft Visual C++ 2017 Redistributable](https://support.microsoft.com/en-us/help/2977003/the-latest-supported-visual-c-downloads) to build pysed.

Required Tools:
  * Visual Studio 2017 (can also use msbuild)
  * Windows 10 SDK version 10.0.16299.0 and SDK version 10.0.17763.0 for Visual Studio 2017
    (ARM and ARM64)
  * MSVC 14.1 

Download boost_1_71_0.zip(https://www.boost.org/users/history/version_1_71_0.html). Create an empty folder "Boost" in the "C:\" drive and extract the zip file into the "C:\Boost" folder.

Download and install Python2.7 at "C:\Python27". Add "C:\Python27" to the Windows path.

Install pip.

Change directory to tcgstorageapi and install python dependencies:

`pip install -r requirements.txt`

#### FreeBSD 12

Start by updating the package index:

`sudo pkg update -f`

Install gcc and gmake:

`sudo pkg install gmake`

`sudo pkg install gcc`

Install python:

`sudo pkg install python2`

Install python packages:

`sudo pkg install <package>`

package:

* py27-boost-libs
* py27-cryptography
* py27-passlib
* py27-openssl
* py27-pycparser
 
### Building

#### Linux

##### CentOS 7

From the terminal, change directory to tcgstorageapi.

Run the command "python setup.py opensea" to build the openseachest libraries. After the command completes, run "python setup.py bdist_rpm" to build an rpm distro.

#### Ubuntu 18.04

From the terminal, link gmake to make by running "sudo ln -s /usr/bin/make /usr/bin/gmake". Change directory to tcgstorageapi.

Run the command "python setup.py opensea" to build the openseachest libraries. After the command completes, run "python setup.py build" to build the pysed library.

#### Windows 10

**Build boost**

Open the Developer Command Prompt for VS2017 and change folder to "C:\Boost\boost_1_71_0" and build boost for Python.

**Build pysed (Visual Studio or msbuild)**

##### Visual Studio
  
Open the solution file in "tcgstorageapi\pysed\Make\VS.2017\pysed.sln".
Set the desired build configuration.
Press "F7" to build pysed, or select "Build->Build All" from the menu.
"pysed" will be output into "tcgstorageapi\pysed\Make\VS.2017\(platform)\(build type)".

Example: `tcgstorageapi\pysed\Make\VS.2017\x64\Static-Release`
  
##### msbuild

From the developer command prompt for VS2017, change directory to "tcgstorageapi\pysed\Make\VS.2017".

Build with the command "msbuild /p:Configuration=(build type) /p:Platform=(platform)".

Example: `msbuild /p:Configuration=Static-Release /p:Platform=x64`

Available Platforms: * Win32 * x64 * ARM * ARM64

Available Build Types: * Static-Release * Static-Debug

#### FreeBSD 12

From the terminal, change directory to tcgstorageapi.

Run the command "python2.7 setup.py opensea" to build the openseachest libraries. After the command completes, run "python2.7 setup.py build" to build the pysed library.

### Installation

#### CentOS

From the tcgstorageapi directory, run "yum install -y  dist/TCGstorageAPI-*.x86_64.rpm" to install the built python package.

#### Ubuntu

Change directory to build/lib.linux-x86_64-2.7. Copy TCGstorageAPI directory to /usr/local/lib/python2.7/site-packages/.

On linux systems, to allow the security commands to reach the SATA drives, set the below flag value to 1:

/sys/module/libata/parameters/allow_tpm

#### Windows 10

Change directory to tcgstorageapi and copy the folder TCGstorageAPI to C:\Python27\Lib\site-packages. Copy pysed\Make\VS.2017\(platform)\(build type)\pysed.sln to C:\Python27\Lib\site-packages\TCGstorageAPI.

**Alternatively, the package can be built and installed using the Dockerfile.**

#### FreeBSD 12

Change directory to build/lib.freebsd-12.1-RELEASE-amd64-2.7. Copy TCGstorageAPI directory to /usr/local/lib/python2.7/site-packages/.

### Docker for Linux

To build the docker image from a Dockerfile, enter the tcgstorageapi directory and run the command as root "sudo docker build -f docker/(OS flavor)/(OS version)/docker-file-name -t docker-image-name ."

Example: `sudo docker build -f docker/CENTOS/7/Dockerfile -t tcgstorageapi-centos .`

The docker container needs to be run in the privileged mode since you are accessing the device. To run the docker container, run the following command "sudo docker run -it --privileged docker-image-name /bin/bash". A new bash shell should appear indicating the running container, you can run the sedcfg.py script from the bash.

Example: `sudo docker run -it --privileged tcgstorageapi-centos /bin/bash`

### Example

Look in the samples directory and run the script sample_cli.py.

WARNING: the credentials for the Admin and Users are hardcoded in the example and should be changed!

The API can support key managers.

The example currently works with 2 bands (TCG Ranges).   

The example script must be run as Administrator/root.
