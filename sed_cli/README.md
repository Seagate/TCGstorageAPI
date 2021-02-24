# sed_cli - Easy to use cli for TCG Storage API

**Copyright (c) 2021 Seagate Technology LLC and/or its Affiliates, All Rights Reserved**

The sed_cli script provides a python based, easy to use command line interface (CLI) for end users.
It supports Enterprise SSC and Opalv2 SSC configurations; see https://trustedcomputinggroup.org/

The CLI is fully functional, but it is not guaranteed to work in all cases.

The script must have low level access to the drives, this requires modifying the drive handle permissions,
or running as Administrator/root 

## To interact with the drive
In order to interact with the drive, the user must pass in the drive handle, this is how the OS communicates with the drive.
They must also pass in an operation indicating how they want to interact with the drive.

Usage: `python3 sed_cli.py --device=<device> --operation=<operation>`

Examples:
- (Linux)   `python3 sed_cli.py --device=/dev/sda --operation=printdriveinfo`
- (Windows) `python3 sed_cli.py --device=PD0 --operation=printdriveinfo`

### KeyManagment
The script supports two different ways of storing credentials: Hashicorp Vault Server, and JSON files

#### JSON
Using the JSON method, the script will store/retrieve credentials via plain text JSON files.
Inherently, this is insecure.  However this method is provided for ease of use, and debugging purposes.
The script will create a separate file, for each drive, the filename will be `<worldwidename>.json`

To use the JSON method, the `--keymanager=json` argument needs to be used.

#### Hashicorp Vault Server
Using a Hashicorp Vault Server, the script will store/retrieve credentials securely using the Vault Server.
The script, will create a separate entry for each drive, indexed by World Wide Name.

Vault Server Setup:
See the bottom of this README for instructions on setting up Hashicorp Vault for use with sed_cli

Configuration file:
The first time the `sed_cli.py` script is run, it will look for a `vaultcfg.json` file.  
If it does not exist,the script will create a blank configuration file.  
The user will need to fill add the server path/url and an authentication token.

The vault keymanager is the default method, if `--keymanager=` is not used, the script will invoke this method.

#### Other
The script is setup in a modular matter, so that additional keymanagers can be implemented, and added.

### Possible Operations
`--operation=<operation>`

**printdriveinfo**
`printdriveinfo` will print out information about the drive.  
It is the default operation, if `--operation=` is not used, the script will invoke this operation.

Usage: `python3 sed_cli.py --device=<device> --operation=printdriveinfo`

Information printed:
Drive Cert - Indicates if the drive is signed with authentic Seagate FW
Drive Handle  - The drive handle being used
TCG Config - Indicates if Enterprise or Opalv2
FIPS Standard\* - Lists the FIPS standard to which the drive is configured \*only available for FIPS configs
FIPS Mode\* - True or False, indicates if the drive is in FIPS mode \*only available for FIPS configs
WWN - The drive's world wide name
MSID - The drive's manufacturing secure ID
MaxLBA - The Max LBA of the drive
is Owned - True or False, indicates if the drive is longer using the default credentials, and is owned
is Locked - True or False, indicates if any LBA bands are currently locked

Also prints information on Port Status:
Port - Name of the Port
Status - Locked or Unlocked
LockOnReset - Enabled or Disabled

#### **takeownership**
`takeownership` will generate a new set of random passwords for each credential, 
replacing the default credentials on the drive.  Credentials will be updated in the KeyManager.

Usage: `python3 sed_cli.py --device=<device> --operation=takeownership`

#### **giveupownership**
`giveupownership` will revert the passwords to their manufacturing default values.
This method will **PRESERVE** all user data.

Usage: `python3 sed_cli.py --device=<device> --operation=giveupownership`

#### **revertdrive**
`revertdrive` will revert the drive to its factory state.
This method will **DELETE** all user data.

Usage: `python3 sed_cli.py --device=<device> --operation=revertdrive`

#### **rotateadminsp**
`rotateadminsp` will generate a new set of random passwords for the AdminSP, 
replacing the current credentials on the drive.  Credentials will be updated in the KeyManager.

Usage: `python3 sed_cli.py --device=<device> --operation=rotateadminsp`

#### **rotatelockingsp**
`rotatelockingsp` will generate a new set of random passwords for the LockingSP and each band, 
replacing the current credentials on the drive.  Credentials will be updated in the KeyManager.

Usage: `python3 sed_cli.py --device=<device> --operation=rotatelockingsp`

#### **configureband**
`configureband` will configure an LBA band as indicated. It uses additional command line options.

Usage: `python3 sed_cli.py --device=<device> --operation=configureband --bandno=<bandno> --rangestart=<rangestart> --rangelength=<rangelength> --lockonreset=<true,false>`

- `bandno` - The band number to configure
- `rangestart` - The LBA number to start the band at (optional)
- `rangelength` - The length, in LBAs, to configure the band with (optional)
- `lockonreset` - Set lockonreset to TRUE or FALSE

#### **lockband**
`lockband` will lock the indicated LBA band.

Usage: `python3 sed_cli.py --device=<device> --operation=lockband --bandno=<bandno>`
- `bandno` - The band number to configure

#### **unlockband**
`unlockband` will unlock the indicated LBA band.

Usage: `python3 sed_cli.py --device=<device> --operation=unlockband --bandno=<bandno>`
- `bandno` - The band number to configure

#### **eraseband**
`eraseband` will erase the indicated LBA band. This will **DELETE** user data on that band.

Usage: `python3 sed_cli.py --device=<device> --operation=eraseband --bandno=<bandno>`
- `bandno` - The band number to configure

#### **configureport**
`configureport` will configure a port as indicated.

Usage: `python3 sed_cli.py --device=<device> --operation=configureport --port=<port> --lockonreset=<true,false>`

- `port` - The port to configure, options are "UDS" and "FWDownload"
- `lockonreset` - Set lockonreset to TRUE or FALSE

#### **lockport**
`lockport` will lock the indicated LBA port.

Usage: `python3 sed_cli.py --device=<device> --operation=lockport --port=<port>`
- `port` - The port number to lock

#### **unlockport**
`unlockport` will unlock the indicated LBA port.

Usage: `python3 sed_cli.py --device=<device> --operation=unlockport --port=<port>`
- `port` - The port to unlock

#### **enablefipsmode**
`enablefipsmode` will enable FIPS mode, by enabling locking on all bands, disabling FW downloads, disabling MakerSim authority, and requiring minimum PIN lengths

Usage: `python3 sed_cli.py --device=<device> --operation=enablefipsmode`

#### **enabletls**
`enabletls` will enable TLS communication, note this is not supported on Windows

Usage: `python3 sed_cli.py --device=<device> --operation=enabletls`

#### **disabletls**
`disabletls` will disable TLS communication

Usage: `python3 sed_cli.py --device=<device> --operation=disabletls`

#### **writedatastore**
`writedatastore` will take a file, up to 768 bytes in size, and write it to the internal SED DataStore

Usage: `python3 sed_cli.py --device=<device> --operation=writedatastore --datain=<filetoread>`
- `datain` - The file to read the data from

#### **readdatastore**
`readdatastore` will read the SED DataStore, and either print it, or write it to file

Usage: `python3 sed_cli.py --device=<device> --operation=writedatastore --dataout=<filetowrite>`
- `dataout` - (Optional) The file to write the data to

## Hashicorp Vault Configuration Instructions
This guide assumes that the user already has an instance of Hashicorp already setup and running.

1. Create the KV Secrets Engine
    - Start at the main GUI page
    - Click "Enable new engine"
    - Select "KV", click "Next"
    - Change Path to "SeagateSecure"
    - Change Version to "1"
    - Click "Enable Engine"

2. Upload/Create the Security Officer and System Administrator policies
    - Start at the main GUI page
    - Click "Policies"
    - Click "Create ACL policy"
    - Fill name with "security-officer-policy", fill policy with contents of security-officer-policy.hcl
    - Click "Create policy"
    - Repeat, but this time with the system-admin-policy

3. Add appropriate policy to each required user.
    - Start at the main GUI page
    - Click "Access"
    - Click the authentication method you have chosen to use, i.e. userpass
    - Create or Edit the target user
    - Click the "Tokens" drop down button
    - Under the "Generated Token's Policies" field, add either "security-officer-policy" or the "system-admin-policy", as desired.
    - If needed, click "Generated Token's Period" and enter a desired lease period.
    - Click "Save"

4. Each user requests their own token
    - Start at the main GUI page
    - Login with the desired user
    - Click the profile image drop down menu, and select "copy token" - Use this token in the vaultcfg.json file

### Role Details
#### Security Officer
Can access AdminSP and LockingSP

Enabling/Disabling data-at-rest functionality and life cycle management of keys
- Enroll
- Disable
- Enable FIPS

#### System Administrator
Can only access Locking SP

Drive Replacement and Drive Decommissioning
- Unlock
- Decommission
- Move drive
- Check FIPS
- Firmware update under FIPS