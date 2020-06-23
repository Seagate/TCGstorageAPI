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
# \file sample_cli.py
# \brief Sample script showing how to use the TCGstorageAPI
#        Note: this script is an example only and uses hardcoded passwords; please change them.
#--------------------------------------------------------------------------------------------------
import os
import sys
import logging
import logging.handlers
import argparse
import struct
import uuid
from TCGstorageAPI.tcgapi import PskCipherSuites
from TCGstorageAPI.tcgapi import Sed
from TCGstorageAPI import keymanager as keymanager
import TCGstorageAPI.tcgSupport as tcgSupport
import helper as verifyidentity
import datetime

class Sedcfg(object):

    '''
    This is a class for performing operations on the SED drive

    Attributes:
        dev: Device handle of the drive.
    '''

    #
    # WARNING! WARNING! WARNING!
    # This sample script uses hardcoded values for the drive credentials.
    # This is not a good security practice.
    # Change these credential values to something more secure (up to 32-bytes in length)!
    #
    cred_table = {
        'SID':          'ADMIN',
        'C_PIN_Admin1': 'ADMIN1',
        'Admin1':       'ADMIN1',
        'C_PIN_User1':  'USER1',
        'User1'      :  'USER1',
        'User2'      :  'USER2',
        'C_PIN_User2':  'USER2',
        'EraseMaster':  'ERASEMASTER',
        'BandMaster0':  'BANDMASTER0',
        'BandMaster1':  'BANDMASTER1',
        'BandMaster2':  'BANDMASTER2'
    }
    
    #NOT_FIPS --> Drive is not a FIPS drive
    #FIPS_MODE --> Drive is a Fips drive and operating in FIPS mode
    #NOT_FIPS_MODE -->Drive is a Fips drive and is not operating in FIPS mode/non-deterministic
    Fips_status = ('NOT_FIPS','FIPS_MODE','NOT_FIPS_MODE')

    def __init__(self, dev):
        '''
        The constructor for the class.

        Parameters:
            dev:Device handle of the drive.
        '''

        os_type = {'linux2':self.linux_platform,'linux':self.linux_platform, 'win32':self.windows_platform, 'freebsd12':self.freebsd_platform}
        os_type[sys.platform](dev)

        logging.basicConfig(
            filename=self.log_filename,
            format="%(asctime)s %(name)s (%(threadName)s) - %(message)s",
            level=logging.DEBUG
        )
        self.logger = logging.getLogger(self.log_filename)
        self.logger.debug('Start sedcfg Logger')
        self.psk = None
        self.keymanager = keymanager.KeyManager()

        # Build the SED object for the drive
        self.sed = Sed(self.devname, callbacks=self)
        for key, val in list(self.cred_table.items()):
            self.keymanager.setKey(key, val)

        self.BandLayout = sedbandlayout()
        self.BandLayout.bandauth(self)
        self.initial_cred = self.sed.mSID

    def linux_platform(self, devname):
        '''
        The function to initialize parameters for the linux platform.

        Parameters:
            devname:Device handle of the drive.
        '''

        self.log_filename = os.path.join(os.path.dirname(__file__), 'sedcfg.log')
        self.devname = devname

    def windows_platform(self, devname):
        '''
        The function to initialize parameters for the windows platform.

        Parameters:
            devname:Device handle of the drive.
        '''

        if getattr(sys, 'frozen', False):
            # frozen
            self.log_filename = os.path.join(os.path.dirname(sys.executable), 'sedcfg.log')
        else:
            # unfrozen
            self.log_filename = os.path.join(os.path.dirname(__file__), 'sedcfg.log')

        # For Windows we need to modify the input value from PD to the physical volume
        # Extract PD from string and take the number value to be used and extrapolate into \\.\PhysicalDrive#

        if ("PD" not in devname):
            print("Please pass drive in as PD<drive number>")
            print("Example: Disk 1 is PD1")
            exit (1)

        drive_number = devname[-1:]
        self.devname = "\\\\.\\PhysicalDrive" + drive_number
        
    def freebsd_platform(self, devname):
        '''
        The function to initialize parameters for the bsd  platorm.
        
        Parameters:
            devanme:Device handle of the drive.
        '''
        
        self.log_filename = os.path.join(os.path.dirname(__file__), 'sedcfg.log')   
        self.devname = devname 
    
    def TlsOperation(self, args=None):
        '''
        The function to enable and disable TLS on the drive.
        Parameters:
            args - Commandline arguments,i.e enable/disable
        '''
        if sys.platform=="win32":
            print("Tls support not provided for Windows")
            return False
        if self.BandLayout.authority[1] == 'Admin1'and self.sed.checkPIN(self.BandLayout.authority[0], self.sed.mSID) == True:
            print("Please perform operation changecreds before Tls enable")
            return False

        authAs = [(self.BandLayout.authority[0], None), (self.BandLayout.authority[1], None)]
        key = tcgSupport.getPsk(self.sed)
        if key == None:
            print("Pre-Shared Key not generated")
            return False
        toUse = self.sed.getPskEntry(0)

        for entryId in range(4):
            psk = self.sed.getPskEntry(entryId)
            if psk is None:
                print("Drive doesn't support TLS")
                return False
            if psk.Enabled == True and int(psk.CipherSuite,16) == PskCipherSuites.Value(self.sed.cipherSuite):
                if args.enabledisable == 'enable':
                    print("Tls already enabled")
                    return True
                if args.enabledisable == 'disable':
                    return self.sed.setPskEntry(toUse, authAs, Enabled=False, CipherSuite=self.sed.cipherSuite, PSK=key)

        if args.enabledisable == 'enable':
            return self.sed.setPskEntry(toUse, authAs, Enabled=True, CipherSuite=self.sed.cipherSuite, PSK=key)
        elif args.enabledisable == 'disable':
            print(" TLS already disabled on the drive")
            return True
        else:
            print("Please enter your input to either enable or disable Tls on the drive")
            return False

    def device_identification(self):
        '''
        The function to perform device identity attestation by validating the device certificate and digital signature
        Uses Tpersign method to sign an input string to return the signature.

        Succeeds if a drive is Seagate specific,fails otherwise

        '''
        self.sed.fipsCompliance = self.sed.fipsCompliance()
        if self.sed.fipsCompliance != None:
            print("Drive being tested is a FIPS drive, device identification not supported")
            return

        # Pull the drive certificate
        self.logger.debug('Obtaining Drive certificate')
        device_cert = self.sed.get_tperSign_cert()
        # Validate the drive_certificate against the root certificate
        identity = verifyidentity.VerifyIdentity(device_cert)
        identity.validate_drive_cert()
        # Send a string to obtain the device signature
        string = str(datetime.datetime.today())
        self.logger.debug('Performing digital signing operation')
        signature = self.sed.tperSign(bytes(string,encoding='utf8'))
        # Validate drive signature
        verify = identity.validate_signature(string, signature)
        if verify == True:
            print("Device identification successfull, drive being tested is a Seagate drive")
        else:
            print("Drive being tested is not a Seagate drive")
        return

    def take_ownership(self, args=None):
        '''
        The function to take owenership of the drive by changing default Admin credentials, to create band authorities and changing
        credentials of the created band authorities.

        Parameters:
           args - Commandline arguments

        Returns:
            True: Successful completion of taking drive ownership.
            False: Failure of taking drive ownership.

        '''
        self.logger.debug('Taking ownership of the drive')
        if  self.sed.checkPIN(self.BandLayout.authority[0], bytes(self.sed.mSID,encoding='utf8')) == False:
            print("Revert the drive to factory state,Drive ownership already taken")
            return False

        # Change PIN of Admin to a new PIN from default value
        good = self.sed.changePIN(self.BandLayout.authority[0], self.keymanager.getKey(self.BandLayout.authority[0]), (None, self.initial_cred))
        if good is True:
            if self.BandLayout.authority[1] == 'Admin1':
            # Activate the Locking SP of the drive only for OPAL case
                if self.sed.activate(self.BandLayout.authority[0]) == False:
                    return False
                self.initial_cred = tcgSupport.getCred(self.keymanager,'SID')
            # Change PIN of Admin of Locking SP
            if self.sed.changePIN(self.BandLayout.authority[1], self.keymanager.getKey(self.BandLayout.authority[1]), (None, self.initial_cred), self.BandLayout.auth_objs[0]) == False:
               return False
            if self.enable_authority() is True:
                print('Credentials of the drive are changed successfully')
                return True
        return False

    def enable_authority(self):
        '''
        The function to enable authorities and change their credentials.

        Returns:
            True: Enable Authority successfull.
            False: Failure to Enable Authority.

        '''
        self.logger.debug('Enable Authority on the drive')
        # Enable two users User1 and User2 and change their password to USER1 and USER2, Bandmaster1 is enabled by default in case of Enterprise.
        for obj in self.BandLayout.auth_objs[3:]:
            if self.sed.enableAuthority(self.BandLayout.authority[1], True, obj) is True:
                continue
            else:
                return False
        # By default global range is enabled in Entperise drives

        if self.BandLayout.enabled_bands:
             if self.sed.changePIN(self.BandLayout.enabled_bands[0], self.keymanager.getKey(self.BandLayout.enabled_bands[0]), (None,  self.initial_cred), self.BandLayout.enabled_bands[0])!= True:
                return False

        # Change pin of band authorities to a new value
        for (obj, auth) in zip(self.BandLayout.auth_objs[1:], self.BandLayout.authority[2:]):
            if self.BandLayout.authority[1] == 'Admin1':
                auth = 'Admin1'
                self.initial_cred = self.keymanager.getKey(auth)
            if self.sed.changePIN(auth, self.keymanager.getKey(obj), (None, self.initial_cred), obj) == False:
                return False
            else:
                continue
        return True

    def configure_bands(self, args):
        '''
        The function to configure bands on the drive and assign bands to authorities.

        Parameters:
            args - Commandline arguments:
                   Bandno: Bandnumber to be configured
                   RangeStart: RangeStart value
                   Rangelength:Rangelength value
                   LockOnReset: True or False

        Returns:
            True: Successfull completion of configuring bands.
            False: Failure to configure bands.
        '''
        self.logger.debug('Configuring bands on the drive')
        if  self.sed.checkPIN(self.BandLayout.authority[0], self.sed.mSID) == True:
            print("Take ownership of  the drive before configuring the drive")
            return False
        # Enable band and set ranges for band
        if self.BandLayout.authority[1] == 'Admin1':
            auth = 'Admin1'
        else:
            auth = 'BandMaster' + args.Bandno

        if auth == 'Admin1' and args.Bandno == '0':
            print("Global range not present in Opal drives")
            return False

        elif args.Bandno == '0' and args.RangeStart != None:
            print("Can't change range for global locking range")
            return False

        elif args.Bandno != '0'and args.RangeStart == None:
            print("Please provide RangeStart and RangeLength values")
            return False

        configure = self.sed.setRange(auth, int(args.Bandno), authAs=(auth, self.keymanager.getKey(auth)), RangeStart=int(args.RangeStart) if args.RangeStart is not None else None, RangeLength=int(args.RangeLength) if args.RangeLength is not None else None,
                                      ReadLockEnabled=1, WriteLockEnabled=1, LockOnReset=args.LockOnReset,
                                      ReadLocked=0, WriteLocked=0)
        if auth == 'Admin1' and configure is True:
        # Give access to users to read and write unlock range only in OPAL case, Bands are assigned to authorities by default in case of Enterprise.
            range_objs = ['ACE_Locking_Range1_Set_RdLocked', 'ACE_Locking_Range1_Set_WrLocked',
             'ACE_Locking_Range2_Set_RdLocked', 'ACE_Locking_Range2_Set_WrLocked']
            if args.Bandno == '1':
                range_obj = range_objs[:2]
            else:
                range_obj = range_objs[2:]
            for objts in range_obj:
                ret = self.sed.enable_range_access(objts, 'User' + args.Bandno, auth)
                if ret == False:
                    return False
        if configure == True:
            print('Band{} is configured'.format(args.Bandno))
            return True
        return False

    def enable_fipsmode(self, args=None):
        '''
        The function to enable FIPS mode on the drive.
         Returns:
            True: Successfull completion of enable fips.
            False: Failure to enable fips.
        '''
        self.logger.debug('Enabling FIPS mode')
        # Retrieve FIPS status
        status = self.fips_status(self.sed)
        if status == "NOT_FIPS":
            return False
        elif status == "FIPS_MODE":
            return True

        # Check the credentials of authorities to confirm ownership
        for auth in self.BandLayout.authority:
            if self.sed.checkPIN(auth, self.sed.mSID) is True:
                print("Please take the ownership of the drive before FIPS enable operation")
                return False

        # Check whether Locking is enabled for any of the bands
        if self.BandLayout.authority[1] == 'Admin1':
            auth, start = 'Admin1', 1
        else:
            auth, start = 'Anybody', 0

        lock_enabled = False
        for bandnumber in range (start, 3):
            locking_info, status = self.sed.getRange(bandnumber, auth)
            if status is True and locking_info is not None:
                if getattr(locking_info, 'ReadLockEnabled') == True or getattr(locking_info, 'WriteLockEnabled') == True:
                    lock_enabled = True
                    break
        if lock_enabled == False:
            print("Please set ReadLockEnabled and WriteLockEnabled to True for any of the enabled bands by performing configure operation")
            return False

        # Disable Makers Authority
        if self.sed.enableAuthority('SID', False, 'Makers') == False:
            print("Failed to disable Makers Authority")
            return False

        # Disable Firmware Download
        for uid in self.sed.ports.keys():
            p = self.sed.getPort(uid)
            if p is not None and hasattr(p, 'Name') and p.Name == 'FWDownload':
                if p.PortLocked != True:
                    if self.sed.setPort(uid, PortLocked=True, LockOnReset=True) == False:
                        print("Failed to disable firmware download port")
                        return False
                print("FIPS mode of the drive enabled successfully")
                return True

    def lock_unlock_bands(self, args):
        '''
        The function to lock and unlock the bands present on the drive

        Parameters:
            args - Command line arguments:
                   lock/unlock: Lock/Unlock the band
                   bandno: Bandnumber

        Returns:
            True : Successfull completion of the operation.
            False: Failure of the operation
        '''
        if  self.sed.checkPIN(self.BandLayout.authority[0], self.sed.mSID) == True:
            print("Take ownership of  the drive and configure band before lock/unlock")
            return False

        if args.bandno == '0' and self.BandLayout.authority[1] == 'Admin1':
            print("Global range not present in Opal drives")
            return False

        Range_info = self.sed.getRange(int(args.bandno), self.BandLayout.authority[1])
        if Range_info == False:
            return False
        print("Band state before lock/unlock =\n{}".format(Range_info[0]))

        self.logger.debug('Locking/Unlocking bands on the drive')
        if(args.lockunlock == "lock"):
            lock_unlock = 1
            if (Range_info[0].ReadLocked == 1):
                print("Band{} already in locked state".format(args.bandno))
                return True
        elif(args.lockunlock == "unlock"):
            lock_unlock = 0
            if (Range_info[0].ReadLocked == 0):
                print("Band{} already in unlocked state".format(args.bandno))
                return True

        # Perform a lock-unlock on the range
        auth = 'User' + args.bandno  if self.BandLayout.authority[1] == 'Admin1' else 'BandMaster' + args.bandno
        lock_unlock = self.sed.setRange(auth, int(args.bandno), authAs=(auth, self.keymanager.getKey(auth)), ReadLocked=lock_unlock, WriteLocked=lock_unlock)
        if lock_unlock == True:
            print("Band{} {}ed successfully by {}".format(args.bandno, args.lockunlock, auth))
            return True
        print("Range not configured properly")
        return False

    def datastore(self, args):
        '''
        The function to read/write small amount of data to the datastore on the drive.
         Returns:
            True: Successfull completion of read/write data.
            False: Failure to read/write data.
        '''

        auth = self.BandLayout.authority[1]
        self.table_number = 0
        if auth == 'Admin1' and self.sed.checkPIN('SID', self.sed.mSID):
            print("Please perform operation changecreds before using the datastore")
            return False

        for entryId in range(4):
            psk = self.sed.getPskEntry(entryId)
            if psk is None:
                break
            if psk.Enabled == True and psk.CipherSuite == self.sed.cipherSuite:
                print("Please disable Tls")
                return False

        self.data = nvdata = {
                'fips':         self.sed.fipsCompliance ,  # Store the FIPS status of the drive.
                'iv':           uuid.uuid4().bytes,  # initialization vector used for hashes/wrappings
                'Ids':          [None, None, None, None],  # keyID for each credential
            }

        self.sed.data_length = (len(tcgSupport.serialize(self.data)))
        self.logger.debug('Reading/Writing data to the datastore on the drive')
        if args.readwrite == "write":
            if auth == 'Admin1':
                if self.sed.writeaccess('User1', self.table_number) == False:
                    return False

            if self.sed.writeData(self.BandLayout.authority[2], self.data) == True:
                return True
            return False

        if args.readwrite == "read":
            if auth == 'Admin1':
                if self.sed.readaccess('User1', self.table_number) == False:
                    return False

            readData = self.sed.readData(self.BandLayout.authority[2])
            if readData == None:
                print("DataStore is empty, no data to read")
                return True
            elif readData == False:
                return False
            print(readData)
        return True

    def erase_drive(self, args):
        '''
        The function to revert the drive back to factory state.

        Parameters:
            args - Commadline arguments.
                   psid: PSID number of the drive

        Returns:
            True : Successfull completion of the operation.
            False: Failure of the operation
        '''
        self.logger.debug('Erasing the drive')
        result = self.sed.revert(args.psid)
        if (result == True):
            return True
        else:
            print("Wrong PSID")
            return False

    @staticmethod
    def fips_status(sed):
        '''
        The function to retrieve the FIPS compliance and FIPS operating mode from the drive

        Parameters:
        sed - SED object

        Returns:
        NOT_FIPS: Drive is not a FIPS drive
        FIPS_MODE: Drive is a Fips drive and operating in FIPS mode
        NOT_FIPS_MODE: Drive is a Fips drive and is not operating in FIPS mode/non-deterministic
        '''
        # Checking Fips Compliance Descriptor
        if sed.fipsCompliance == None or sed.fipsCompliance["standard"] != "FIPS 140-2" and sed.fipsCompliance["standard"] != "FIPS 140-3":
            print ("Drive doesn't support FIPS 140-2 or FIPS 140-3 Standard")
            return Sedcfg.Fips_status[0]

        #This uses Seagate Vendor Unique functionality, and may not be supported by other vendors
        #May not work on older Seagate models
        if sed.fipsApprovedMode is True:
            print ("Drive operating in FIPS mode")
            return Sedcfg.Fips_status[1]
        else:
            return Sedcfg.Fips_status[2]


class sedbandlayout(object):
    '''
    This a class defining the band Layout of the drive.
    '''

    # Class can be modified to add multiple users in a dynamic fashion
    def __init__(self):

        '''
        The function defines parameters for the BandLayout of the drive.
        '''
        self.Ent_auth = ['SID', 'EraseMaster', 'BandMaster1', 'BandMaster2']
        self.Opal_auth = ['SID', 'Admin1', 'User1', 'User2']
        self.Ent_objs = ['EraseMaster', 'BandMaster1', 'BandMaster2', 'C_PIN_BandMaster1', 'C_PIN_BandMaster2']
        self.Opal_objs = ['C_PIN_Admin1', 'C_PIN_User1', 'C_PIN_User2', 'User1', 'User2']

    def bandauth(self, sedbandcfg):
        '''
        The function to choose between Enterprise and Opal band layout.
        '''
        if sedbandcfg.sed.SSC == 'Enterprise':
            self.authority = self.Ent_auth
            self.auth_objs = self.Ent_objs
            self.enabled_bands = ['BandMaster0']
        else:
            self.authority = self.Opal_auth
            self.auth_objs = self.Opal_objs
            self.enabled_bands = None


class argParser(object):
    '''
    This is a class to parse the command line arguments.
    '''
    prog = 'sample_cli'
    description = 'Sample CLI that implements TCG protocol for SED operations'

    def getParser(self):
        '''
        The Function to parse command line arguments and initialize operations.
        '''

        main = self.main = argparse.ArgumentParser(
            prog=self.prog,
            description=self.description,
        )

        main.add_argument('device', help='Specific wwn or device names of drives to operate on')
        subparser = main.add_subparsers(title='subcommand')
        enableTls = subparser.add_parser('Tls', help='EnableTls on the Drive')
        enableTls.add_argument('enabledisable', help='enable or disable Tls communication')
        enableTls.set_defaults(operation=Sedcfg.TlsOperation)
        datastore = subparser.add_parser('store', help='Use the DataStore on the Drive')
        datastore.add_argument('readwrite', help='Read/Write the data from the DataStore')
        datastore.set_defaults(operation=Sedcfg.datastore)
        revert = subparser.add_parser('revert', help='Revert the drive back to factory state')
        revert.add_argument('psid', help='PSID of the drive used to revert the drive back to factory state')
        revert.set_defaults(operation=Sedcfg.erase_drive)
        changecreds = subparser.add_parser('changecreds', help='Change the drive default credentials')
        changecreds.set_defaults(operation=Sedcfg.take_ownership)
        configure = subparser.add_parser('configure', help='Configure the bands by setting new band ranges')
        configure.add_argument('Bandno', help='Band number to configure')
        configure.add_argument('--RangeStart', help='Rangestart value, Default(4097)')
        configure.add_argument('--RangeLength', help='RangeLength value, Default(219749770)')
        configure.add_argument('LockOnReset', help='True or False value for LockOnReset')
        configure.set_defaults(operation=Sedcfg.configure_bands)
        enablefips = subparser.add_parser('enablefips', help='Enable FIPS mode on the fips drive')
        enablefips.set_defaults(operation=Sedcfg.enable_fipsmode)
        bandops = subparser.add_parser('bandops', help='Perform a lock or an unlock on the band')
        bandops.add_argument('lockunlock', help='Lock, Unlock the band')
        bandops.add_argument('bandno', help='band number to be locked unlocked')
        bandops.set_defaults(operation=Sedcfg.lock_unlock_bands)
        return main

    def doParse(self, args):
        '''
        The function to obtain arguments.
        '''
        if args is not None:
            args = shlex.split(args)
        else:
            args = sys.argv[1:]
        namespace = self.getParser().parse_args(args)

        return namespace


def main(args=None):
    drive_namespace = argParser().doParse(args)
    sedcfg = Sedcfg(drive_namespace.device)
    if sedcfg.sed.SSC != 'Enterprise' and sedcfg.sed.SSC != 'Opalv2':
        print("Unable to retrieve SED functionality of the device. Enable OS to allow secure commands ")
        return 1
    sedcfg.device_identification()
    rv = drive_namespace.operation(sedcfg, drive_namespace)
    if rv is not True:
        print("Operation failed")
        return 1
    else:
        print("Operation completed successfully")


if __name__ == "__main__":
    sys.exit(main())
