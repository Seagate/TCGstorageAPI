# Example Script for TCG Storage API

##### Copyright (c) 2020 Seagate Technology LLC and/or its Affiliates, All Rights Reserved

The sample script creates a sample CLI that implements commands to configure a SED and shows how
to use the underlying TCGstorageAPI. The Trusted Computing Group (TCG) Storage Application Notes
for Enterprise SSC and Opal SSC were used as a reference; see https://trustedcomputinggroup.org/

Note that the CLI is an example only, not guaranteed to work in all cases and only uses a subset of the full API.

The example currently works with 2 bands (TCG Ranges) only and must be run as Administrator/root.

### Example commands for CLI

**To take ownership of the drive by changing its credentials:**

Usage: `python3 sample_cli.py <device> <operations>`

Examples:
- (Linux)   `python3 sample_cli.py /dev/sd? changecreds`
- (Windows) `python3 sample_cli.py PD? changecreds`

Note: this results in change of default Admin password of the drive. Trying to perform the operation for a second time on the drive without a revert will fail.


**To configure bands on the drive:**

Usage: `python3 sample_cli.py <device> <operations> <flags>`

Examples:
- `python3 sample_cli.py /dev/sd? configure 0 True`
- `python3 sample_cli.py /dev/sd? configure 1 --RangeStart 8 --RangeLength 64 True`
- `python3 sample_cli.py /dev/sd? configure 2 --RangeStart 80 --RangeLength 88 False`

Instructions for setting band values:  
- For the RangeStart input a value that is a multiple of 8 to maintain sector alignment.
- RangeLength cannot exceed the maximum sector size of the drive.
- Maintain difference between 2 band ranges. In other words band ranges cannot overlap.


**To lock/unlock the configured bands:**

Usage: `python3 sample_cli.py <device> <operations> <flags>`

Examples:
- `python3 sample_cli.py /dev/sd? bandops lock 1`
- `python3 sample_cli.py /dev/sd? bandops unlock 2`


**To revert the drive back to factory state:**

Usage: `python3 sample_cli.py <device> <operations> <flags>`

Example:
- `python3 sample_cli.py	/dev/sd? revert psidnumberofthedrive`


**To Enable FIPS mode:**
Take Ownership of the drive first by running `changecreds`, otherwise FIPS enable will fail.

Usage: `python3 sample_cli.py <device> <operations>`

Example:    
- `python3 sample_cli.py /dev/sd? enablefips`


**To Enable TLS or Disable TLS secure messaging:**

TLS operations are not supported on Windows OS.

On Opal drives, make sure to change the default credentials and activate lockingSP first by running "changecreds".

***WARNING: The generated PSK is stored in a file. This is insecure! In reality the file needs to be replaced by a local keystore or remote key manager.***

Usage: `python3 sample_cli.py <device> <operations> <flags>`

Examples:
- `python3 sample_cli.py /dev/sd? Tls enable`
- `python3 sample_cli.py /dev/sd? Tls disable`

Note: To enable debug for gnuTLS on Linux, use `export GNUTLS_DEBUG_LEVEL=4`

**To read/write data into the DataStore:**

Note: Read/write data does currently not work with TLS enabled.

Usage: `python3 sample_cli.py <device> <operations> <flags>`

Examples:   
- `python3 sample_cli.py /dev/sd? store read`
- `python3 sample_cli.py /dev/sd? store write`

**To enable FW attestation on the drive:**

Usage: `python3 sample_cli.py <device> <operations> <flags>`

Examples:   
- `python3 sample_cli.py /dev/sd? fwattest enable`