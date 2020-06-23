[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
# TCGstorageAPI

## API for TCG Storage operations on SAS and SATA Self-Encrypting Drives

##### Copyright (c) 2020 Seagate Technology LLC and/or its Affiliates, All Rights Reserved

![](https://github.com/Seagate/TCGstorageAPI/workflows/TCGstorageAPI%20build/badge.svg)

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

Install Python3 setup tools:

`sudo apt-get install python3-setuptools`

Change directory to tcgstorageapi and download the package dependencies:

`pip3 install --no-cache-dir -r requirements.txt`

#### Windows 10

Your system will require the latest [Microsoft Visual C++ 2017 Redistributable](https://support.microsoft.com/en-us/help/2977003/the-latest-supported-visual-c-downloads) to build pysed.

Required Tools:
  * Visual Studio 2017 (can also use msbuild)
  * Windows 10 SDK version 10.0.16299.0 and SDK version 10.0.17763.0 for Visual Studio 2017
    (ARM and ARM64)
  * MSVC 14.1 

Download boost_1_71_0.zip(https://www.boost.org/users/history/version_1_71_0.html). Create an empty folder "Boost" in the "C:\" drive and extract the zip file into the "C:\Boost" folder.

Download and install Python3.8 at "C:\Python38". Add "C:\Python38" to the Windows path.

Install pip3.

Change directory to tcgstorageapi and install python3 dependencies:

`pip3 install -r requirements.txt`

#### FreeBSD 12

Start by updating the package index:

`sudo pkg update -f`

Install gcc and gmake:

`sudo pkg install gmake`

`sudo pkg install gcc`

Install python:

`sudo pkg install python`

Install python packages:

`sudo pkg install <package>`

package:

* py37-boost-libs-1.72.0
* py37-cryptography
* py37-passlib
* py37-openssl
* py37-pycparser
* py37-setuptools-41.4.0_1

### Building

#### Linux

##### CentOS 7

From the terminal, change directory to tcgstorageapi. 

Run the command "python3 setup.py opensea" to build the openseachest libraries. After the command completes, run "python3 setup.py bdist_rpm" to build an rpm distro. 

##### Ubuntu 18.04

From the terminal, link gmake to make by running "sudo ln -s /usr/bin/make /usr/bin/gmake".
Change directory to tcgstorageapi.

Run the command "python3 setup.py opensea" to build the openseachest libraries. After the command completes, run "python3 setup.py build" to build the library.

#### Windows 10

**Build boost**

Open the Developer Command Prompt for VS2017 and change folder to "C:\Boost\boost_1_71_0" and build boost for Python3.

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

Available Platforms: * Win32 * x64 * ARM  * ARM64

Available Build Types: * Static-Release * Static-Debug

#### FreeBSD 12

From the terminal, change directory to tcgstorageapi.

Run the command "python3.7 setup.py opensea" to build the openseachest libraries. After the command completes, run "python3.7 setup.py build" to build the pysed library.

### Installation

#### Centos 7

From the tcgstorageapi directory, run "yum install -y  dist/TCGstorageAPI-*.x86_64.rpm" to install the built python3 package.

#### Ubuntu 18.04

Change directory to build/lib.linux-x86_64-3.6. Copy TCGstorageAPI directory to /usr/local/lib/python3/dist-packages/.

On linux systems, to allow the security commands to reach the SATA drives, set the below flag value to 1:

/sys/module/libata/parameters/allow_tpm

#### Windows 10

Change directory to tcgstorageapi and copy the folder TCGstorageAPI to C:\Python38\Lib\site-packages. Copy pysed\Make\VS.2017\(platform)\(build type)\pysed.pyd to C:\Python38\Lib\site-packages\TCGstorageAPI.

**Alternatively, the package can be built and installed using the Dockerfile**.

#### FreeBSD 12

Change directory to build/lib.freebsd-12.1-RELEASE-amd64-3.7. Copy TCGstorageAPI directory to /usr/local/lib/python3.7/site-packages/.

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
