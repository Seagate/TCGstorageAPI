#----------------------------------------------------------------------------
# Do NOT modify or remove this copyright
#
# Copyright (c) 2021 Seagate Technology LLC and/or its Affiliates
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

import argparse
import datetime
import json
import logging
import os
import sys
import textwrap
import time
import uuid
import filecmp

## Add TCGstorageAPI path
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))

import TCGstorageAPI.tcgSupport as tcgSupport
import CertificateValidation as verifyIdentity
from TCGstorageAPI.tcgapi import Sed as SED
from keymanager import keymanager_vault
from keymanager import keymanager_json

def auto_int(x):
    return int(x, 0)

def str2bool(v):
    if isinstance(v, bool):
       return v
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')

def parse_args():
    epilogue = textwrap.dedent('''
         =======================================================================================================
         = This CLI is fully functional, but it is not guaranteed to work in all cases.  Use at your own risk. =
         =======================================================================================================
         ''')

    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter, epilog=epilogue)

    parser.add_argument('--bandno', default=0, type=int,
                        help='The band to operate on')

    parser.add_argument('--datain', default=None,
                        help='The file to write to the SED datastore')

    parser.add_argument('--dataout', default=None,
                        help='Write the SED datastore to this file')

    parser.add_argument('--device', default=None,
                        help='The OS path to the device under operation')

    parser.add_argument('--keymanager', default='vault', choices=('json', 'vault'),
                        help='The keymanager to use')

    parser.add_argument('--lockonreset', type=str2bool, choices=('true', 'false'),
                        help='Enable/Disable lock on reset')

    parser.add_argument('--logfile', default='sedcfg.log',
                        help='The filename of the logfile to write')

    parser.add_argument('--port', default='',
                        help='The port to lock or unlock')

    parser.add_argument('--psid', default=None,
                        help='The PSID of the drive, used for factory restore, found on drive label')

    parser.add_argument('--rangestart', default=None, type=auto_int,
                        help='The LBA to start the band at')

    parser.add_argument('--rangelength', default=None, type=auto_int,
                        help='The length of the band')

    parser.add_argument('--vaultconfig', default='vaultcfg.json',
                        help='The filename of the vault config file')

    parser.add_argument('--operation', default='printdriveinfo', choices=(
        'configureband',
        'configureport',
        'debug',
        'disabletls',
        'enablefipsmode',
        'enabletls',
        'fwattestation',
        'giveupownership',
        'eraseband',
        'lockband',
        'lockport',
        'printbandinfo',
        'printdriveinfo',
        'readdatastore',
        'revertdrive',
        'rotateadminsp',
        'rotatelockingsp',
        'takeownership',
        'unlockband',
        'unlockport',
        'validateseagate',
        'writedatastore',
        'unittest',
    ))

    opts = parser.parse_args()

    if opts.operation in ['revertdrive', 'unittest'] and not opts.psid:
        parser.error('--psid argument is mandatory for the revertdrive and unittest operations')

    if opts.operation == 'writedatastore' and not opts.datain:
        parser.error('--datain argument is mandatory for the writedatastore operation')

    if not opts.device:
        parser.error('--device argument is mandatory')

    return opts

#***********************************************************************************************************************
class cSEDConfig(object):
    def __init__(self, deviceHandle, KeyManagerType, opts):

        ## Initialize Class Variables
        self.opts = opts
        self.log_filename = self.opts.logfile
        self.deviceHandle = deviceHandle
        self.driveType = None
        self.LockingSP = None
        self.LockingSP_Obj = None
        self.AdminSP = 'SID'
        self.initialBandList = list()

        ## Initialize Logger
        logging.basicConfig(
            filename=self.log_filename,
            format='%(asctime)s %(name)s (%(threadName)s) - %(message)s',
            level=logging.DEBUG)
        self.logger = logging.getLogger(self.log_filename)

        ## Initialize KeyManager
        if KeyManagerType == 'vault':  ## Vault KeyManager
            self.keyManager = keymanager_vault.keymanager_vault(self.opts.vaultconfig)

        elif KeyManagerType == 'json': ## JSON KeyManager
            self.keyManager = keymanager_json.keymanager_json()
        else:
            print('Unknown KeyManager Type!')
            sys.exit(1)

        ## Initialize the SED object
        self.SED = SED(self.deviceHandle, callbacks=self)
        
        ## Get the WWN in string format
        self.wwn = format(self.SED.wwn, 'X')
        
        ## Initialize the mSID
        self.initial_cred = self.SED.mSID

        ## Configure variables based on security type
        if self.SED.SSC == 'Enterprise':
            self.logger.info('SED configuration is Enterprise')
            self.LockingSP = 'EraseMaster'
            self.LockingSP_Obj = None
            self.initialBandList.append('BandMaster0')
            self.initialBandList.append('BandMaster1')

        elif self.SED.SSC == 'Opalv2':
            self.logger.info('SED configuration is Opalv2')
            self.LockingSP = 'Admin1'
            self.LockingSP_Obj = 'C_PIN_Admin1'
            self.initialBandList.append('User1')

        else:
            print('SED configuration is Unknown/Unsupported (Type {}) - Exiting Script'.format(self.SED.SSC))
            sys.exit()

    #********************************************************************************
    ##        name: printDriveInfo
    #  description: Prints various information about the drive to console
    #       output:
    #              Drive Handle: The handle of the drive (ex /dev/sdb)
    #              WWN: The drive's unique World Wide Name
    #                   Drives with multiple ports will have a unique WWN for each port
    #              MSID: The drive's unique Manufactures Secure ID number
    #              MaxLBA: The MaxLBA of the drive, in HEX
    #              IsLocked: True if any LBA bands are locked, otherwise False
    #********************************************************************************
    def printDriveInfo(self):
        print('Drive Handle   = {}'.format(self.deviceHandle))
        print('TCG Config     = {}'.format(self.SED.SSC))
        if self.SED.fipsCompliance():
            print('FIPS Standard  = {}'.format(self.SED.fipsCompliance()['standard']))
            print('FIPS Mode      = {}'.format(self.SED.fipsApprovedMode))
        print('WWN            = {:X}'.format(self.SED.wwn))
        print('MSID           = {}'.format(self.SED.mSID))
        print('MaxLBA         = 0x{:X}'.format(self.SED.maxLba))
        print('Is Owned       = {}'.format(self.isOwned()))
        print('Is Locked      = {}'.format(self.SED.hasLockedRange))

    #********************************************************************************
    ##        name: printSecurityInfo
    #  description: Prints various information about the drive's state to console
    #********************************************************************************
    def printSecurityInfo(self):
        if self.SED.SSC == 'Enterprise':
            SEDInfo = self.SED.lockingInfo()
            print('Max Ranges = {}'.format(SEDInfo.MaxRanges))
            print('Encryption Support = {}'.format(SEDInfo.EncryptSupport))
            print('BlockSize = {}'.format(SEDInfo.LogicalBlockSize))
            print('LowestAlignedLBA = {}'.format(SEDInfo.LowestAlignedLBA))
            print('AlignmentGranularity = {}'.format(SEDInfo.AlignmentGranularity))
            print('AlignmentRequired = {}'.format(SEDInfo.AlignmentRequired))
            print('MaxReEncryptions = {}'.format(SEDInfo.MaxReEncryptions))
            print('KeysAvailableCfg = {}'.format(SEDInfo.KeysAvailableCfg))

    #********************************************************************************
    ##        name: takeOwnership
    #  description: Takes ownership of a drive by replacing the initial credentials
    #               with unique values, which are saved to the KeyManager
    #       return: False if successfull
    #               True if failure
    #********************************************************************************
    def takeOwnership(self):
        failureStatus = False

        # Check that SID is unowned
        if not self.SED.checkPIN(self.AdminSP, self.initial_cred):
            print('Ownership of SID already taken')
            failureStatus = True
            return failureStatus

        # Initialize keyManager with default SID
        self.keyManager.setKey(self.wwn, self.AdminSP, self.initial_cred)

        # Take Ownership of AdminSP
        newKey = self.keyManager.generateRandomValue()
        self.SED.changePIN(self.AdminSP, newKey, (None, self.initial_cred))
        if self.SED.checkPIN(self.AdminSP, newKey):
            print('Took ownership of AdminSP ({})'.format(self.AdminSP))
            self.keyManager.setKey(self.wwn, self.AdminSP, newKey)
        else:
            print('Failed to take ownership of AdminSP ({})'.format(self.AdminSP))
            failureStatus = True

        # If Opalv2, AdminSP needs to be activated
        if self.SED.SSC == 'Opalv2':
            if self.SED.activate(self.AdminSP, authAs=(self.AdminSP, self.keyManager.getKey(self.wwn, self.AdminSP))):
                print('Activated AdminSP ({})'.format(self.AdminSP))
            else:
                print('Failed to activate AdminSP ({})'.format(self.AdminSP))

        # Take Ownership of LockingSP
        if self.SED.SSC == 'Enterprise':
            initialKey = self.initial_cred
        elif self.SED.SSC == 'Opalv2':
            initialKey = self.keyManager.getKey(self.wwn, self.AdminSP)
        else:
            failureStatus = True
            return failureStatus

        newKey = self.keyManager.generateRandomValue()
        self.SED.changePIN(self.LockingSP, newKey, (None, initialKey), self.LockingSP_Obj)
        if self.SED.checkPIN(self.LockingSP, newKey):
            print('Took ownership of LockingSP ({})'.format(self.LockingSP))
            self.keyManager.setKey(self.wwn, self.LockingSP, newKey)
        else:
            print('Failed to take ownership of LockingSP({})'.format(self.LockingSP))

        # Take Ownership of Bands
        for bandOwner in self.initialBandList:
            newKey = self.keyManager.generateRandomValue()

            # Setup variables for each config
            if self.SED.SSC == 'Enterprise':
                auth = bandOwner
                authAs = (None, self.initial_cred)
                obj = None
            elif self.SED.SSC == 'Opalv2':
                auth = self.LockingSP
                authAs = (None, self.keyManager.getKey(self.wwn, self.LockingSP))
                obj = 'C_PIN_{}'.format(bandOwner)

                # If Opalv2, bands needs to be activated first
                if self.SED.enableAuthority(self.LockingSP, True, bandOwner, authAs=(self.LockingSP, self.keyManager.getKey(self.wwn, self.LockingSP))):
                    self.logger.debug('Enabled {}'.format(bandOwner))
                else:
                    print('Failed to enable {}'.format(bandOwner))
                    failureStatus = True
            else:
                return True

            # Take ownership
            self.SED.changePIN(auth, newKey, authAs, obj)
            if self.SED.checkPIN(bandOwner, newKey):
                print('Took ownership of {}'.format(bandOwner))
                self.keyManager.setKey(self.wwn, bandOwner, newKey)
            else:
                print('Failed to take ownership of {}'.format(bandOwner))

        return failureStatus

    #********************************************************************************
    ##        name: rotateAdminSP
    #  description: Retrieves the password of each user from the KeyManager,
    #               changes the password of each user on the drive,
    #               saves the updated passwords to the KeyManager
    #********************************************************************************
    def rotateAdminSP(self, giveUpOwnership = False):
        failureStatus = False

        # Create correct verb for message
        if giveUpOwnership:
            verb1 = 'Gave Up'
            verb2 = 'Give Up'
        else:
            verb1 = 'Updated'
            verb2 = 'Update'

        if not self.keyManager.getKey( self.wwn, 'SID' ):
            print('Unable to access AdminSP - rotateAdminSP Failed')
        else:
            # Rotate AdminSP
            if giveUpOwnership:
                newKey = self.initial_cred
            else:
                newKey = self.keyManager.generateRandomValue()
            self.SED.changePIN(self.AdminSP, newKey, (None, self.keyManager.getKey(self.wwn, self.AdminSP)))
            if self.SED.checkPIN(self.AdminSP, newKey):
                print('{} AdminSP ({})'.format(verb1, self.AdminSP))
                self.keyManager.setKey(self.wwn, self.AdminSP, newKey)
            else:
                print('{} AdminSP ({})'.format(verb2, self.AdminSP))
                failureStatus = True

        return failureStatus

    #********************************************************************************
    ##        name: rotateKeys
    #  description: Retrieves the password of each user from the KeyManager,
    #               changes the password of each user on the drive,
    #               saves the updated passwords to the KeyManager
    #********************************************************************************
    def rotateLockingSP(self, giveUpOwnership = False):

        # Create correct verb for message
        if giveUpOwnership:
            verb1 = 'Gave Up'
            verb2 = 'Give Up'
        else:
            verb1 = 'Updated'
            verb2 = 'Update'

        # Rotate Band Keys
        for bandOwner in self.keyManager.getBandNames(self.wwn):
            if giveUpOwnership:
                newKey = self.initial_cred
            else:
                newKey = self.keyManager.generateRandomValue()

            # Setup variables for each config
            if self.SED.SSC == 'Enterprise':
                auth = bandOwner
                authAs = (None, self.keyManager.getKey(self.wwn, bandOwner))
                obj = None
            elif self.SED.SSC == 'Opalv2':
                auth = self.LockingSP
                authAs = (None, self.keyManager.getKey(self.wwn, self.LockingSP))
                obj = 'C_PIN_{}'.format(bandOwner)
            else:
                return True
            
            # Update keys
            self.SED.changePIN(auth, newKey, authAs, obj)
            if self.SED.checkPIN(bandOwner, newKey):
                print('{} {}'.format(verb1, bandOwner))
                self.keyManager.setKey(self.wwn, bandOwner, newKey)
            else:
                print('Failed to {} {}'.format(verb2, bandOwner))
                failureStatus = True

        # Rotate LockingSP
        if giveUpOwnership:
            newKey = self.initial_cred
        else:
            newKey = self.keyManager.generateRandomValue()
        currentKey = self.keyManager.getKey(self.wwn, self.LockingSP)
        self.SED.changePIN(self.LockingSP, newKey, (None, currentKey), self.LockingSP_Obj)
        if self.SED.checkPIN(self.LockingSP, newKey):
            print('{} LockingSP ({})'.format(verb1, self.LockingSP))
            self.keyManager.setKey(self.wwn, self.LockingSP, newKey)
        else:
            print('Failed to {} LockingSP({})'.format(verb2, self.LockingSP))
            failureStatus = True

        # Special case for Opalv2
        if giveUpOwnership and self.SED.SSC == 'Opalv2':
            if self.SED.revert_lockingSP(self.keyManager.getKey(self.wwn, self.LockingSP)):
                print('Reverted LockingSP ({})'.format(self.LockingSP))
            else:
                print('Failed to revert LockingSP ({})'.format(self.LockingSP))
                failureStatus = True

    #********************************************************************************
    #  description: Gives up ownership of a drive by resetting credentials to default
    #               Note - this method RETAINS USER DATA
    #********************************************************************************
    def giveUpOwnership(self):
        failureStatus = False

        if not self.keyManager.getKey( self.wwn, 'SID' ):
            print('Unable to access AdminSP - giveUpOwnership Failed')
        else:
            if self.rotateLockingSP(giveUpOwnership=True):
                print('Failed to give up LockingSP')
                failureStatus = True
            elif self.rotateAdminSP(giveUpOwnership=True):
                print('Failed to give up AdminSP')
                failureStatus = True
            else:
                # Unlock Ports
                self.configurePort('UDS', False, False)
                self.configurePort('FWDownload', False, False)
                self.keyManager.deletePasswords(self.wwn)

        return failureStatus

    #********************************************************************************
    ##        name: revertDrive
    #  description: Allows the user to revert the drive to factory settings
    #********************************************************************************
    def revertDrive(self):
        if self.SED.revert(self.opts.psid):
            print('Drive succesfully erased and reverted to factory settings')
            self.keyManager.deletePasswords(self.wwn)
            return True
        else:
            print('Drive was not erased, check that the PSID is correct')
            print('Entered PSID - \'{}\''.format(self.opts.psid))
            return False

    #********************************************************************************
    ##        name: configureBands
    #  description: Allows the user to configure a custom LBA band
    #   parameters:
    #               bandNumber - The band number to configure
    #               rangeStart - The LBA to start at
    #              rangeLength - The Length of the desired LBA band
    #               lock_state - Lock the Band
    #      lock_on_reset_state - Indicate if the band should lock on reset
    #      return : False - No issues
    #                True - Errors occurred
    #********************************************************************************
    def configureBands(self, bandNumber=0, rangeStart=None, rangeLength=None, lock_state=False, lock_on_reset_state=True):
        self.logger.debug('Configuring bands on the drive')
        if self.SED.checkPIN('SID', bytes(self.SED.mSID, encoding='utf8')) == True:
            print('Take ownership of drive before configuring a band')
            return True

        ## Configure Band
        if self.SED.SSC == 'Enterprise':
            auth = 'BandMaster{}'.format(bandNumber)
            if auth not in self.keyManager.getBandNames(self.wwn):
                # Add band, if it hasn't been enabled yet
                self.enableBand(bandNumber)
        else:
            auth = 'Admin1'
            if bandNumber == 0:
                print('Opalv2 does not support Global Range')
                return True
            elif 'User{}'.format(bandNumber) not in self.keyManager.getBandNames(self.wwn):
                # Add band, if it hasn't been enabled yet
                self.enableBand(bandNumber)

        if bandNumber == 0 and (rangeStart or rangeLength):
            print('Changing range for Band 0 (global locking range) is not allowed.')
            return True

        configureStatus = self.SED.setRange(
            auth,
            int(bandNumber),
            authAs=(auth, self.keyManager.getKey(self.wwn, auth)),
            RangeStart=int(rangeStart) if rangeStart is not None else None,
            RangeLength=int(rangeLength) if rangeStart is not None else None,
            ReadLockEnabled=1,
            WriteLockEnabled=1,
            LockOnReset=lock_on_reset_state,
            ReadLocked=lock_state,
            WriteLocked=lock_state,
            )

        #If Opalv2, allow the User to access the band
        if self.SED.SSC == 'Opalv2':
            for object in [
                'ACE_Locking_Range{}_Set_RdLocked'.format(bandNumber), 
                'ACE_Locking_Range{}_Set_WrLocked'.format(bandNumber)]:
                self.SED.enable_range_access(
                    object, 
                    'User{}'.format(bandNumber),
                    'Admin1',
                    ('Admin1', self.keyManager.getKey(self.wwn, 'Admin1')))

        if configureStatus:
            print('Band{} is configured'.format(bandNumber))
            return False
        else:
            print('Error configuring Band{}'.format(bandNumber))
            return True

    #********************************************************************************
    ##        name: lockunlockBand
    #  description: Allows the user to lock/unlock the indicated band
    #   parameters:
    #               bandNumber - The band to lock/unlock
    #               lock_state - If true, lock the band. If false, unlock the band
    #********************************************************************************
    def lockunlockBand(self, bandNumber, lock_state):
        if self.SED.SSC == 'Enterprise':
            return self.configureBands(bandNumber, lock_state=lock_state)

        elif self.SED.SSC == 'Opalv2':
            if bandNumber == 0:
                print('Opalv2 does not support Global Range')
                return True
            user = 'User{}'.format(bandNumber)
            if self.SED.setRange(
                user,
                int(bandNumber),
                (user, self.keyManager.getKey(self.wwn, user)),
                ReadLocked=lock_state, WriteLocked=lock_state):
                if lock_state:
                    print('Locked Band{}'.format(bandNumber))
                else:
                    print('Unlocked Band{}'.format(bandNumber))
            else:
                if lock_state:
                    print('Error Locking Band{}'.format(bandNumber))
                else:
                    print('Error Unlocking Band{}'.format(bandNumber))

    #********************************************************************************
    ##        name: lockBand
    #  description: Allows the user to lock the indicated band
    #   parameters: bandNumber - The band to lock
    #********************************************************************************
    def lockBand(self, bandNumber):
        return self.lockunlockBand(bandNumber, True)

    #********************************************************************************
    ##        name: unlockBand
    #  description: Allows the user to unlock the indicated band
    #   parameters: bandNumber - The band to unlock
    #********************************************************************************
    def unlockBand(self, bandNumber):
        return self.lockunlockBand(bandNumber, False)

    #********************************************************************************
    ##        name: eraseBand
    #  description: Allows the user to erase the indicated band
    #   parameters: bandNumber - The band to erase
    #********************************************************************************
    def eraseBand(self, bandNumber):
        if self.SED.SSC == 'Enterprise':
            user = 'BandMaster{}'.format(bandNumber)
            if self.SED.erase(bandNumber, authAs=('EraseMaster', self.keyManager.getKey(self.wwn, 'EraseMaster'))):
                print('Band{} sucessfully erased'.format(bandNumber))
                
                # In Enterprise, band erasure will revert ownership, so delete the band from the key list
                self.keyManager.deleteKey(self.wwn, user)

                # Then reenable
                self.enableBand(bandNumber)
                return True
            else:
                print('Error - Band{} was not erased'.format(bandNumber))
                return False

        elif self.SED.SSC == 'Opalv2':
            user = 'User{}'.format(bandNumber)

            # Get the raw range_key from the get_MEK function
            m1, m2 = self.SED.get_MEK(bandNumber, 'Admin1', ('Admin1', self.keyManager.getKey(self.wwn, 'Admin1')))

            # Which object we want is based on the range number, so we use the getattr function
            method_to_call = getattr(m1, 'K_AES_256_Range{}_Key_UID'.format(bandNumber))
            range_key = int.from_bytes(method_to_call, 'big')

            if self.SED.gen_key(
                range_key,
                'Admin1',
                ('Admin1', self.keyManager.getKey(self.wwn, 'Admin1'))):
                print('Band{} sucessfully erased'.format(bandNumber))
                return True
            else:
                print('Error - Band{} was not erased'.format(bandNumber))
                return False

    #********************************************************************************
    ##        name: enableBand
    #  description: Allows the user to add the indicated band
    #   parameters: bandNumber - The band to add
    #********************************************************************************
    def enableBand(self, bandNumber):
        failureStatus = False

        if self.SED.checkPIN('SID', bytes(self.SED.mSID, encoding='utf8')) == True:
            print('Take ownership of drive before adding a band')
            return True

        if self.SED.SSC == 'Enterprise':
            newKey = self.keyManager.generateRandomValue()

            # Setup variables for each config
            bandOwner = 'BandMaster{}'.format(bandNumber)
            authAs = (None, self.initial_cred)
            obj = None

            # Enable The Band
            self.SED.enableAuthority(bandOwner, True, obj="C_PIN_{}".format(bandOwner), authAs=("EraseMaster", self.keyManager.getKey(self.wwn, "EraseMaster")))

            # Take ownership
            self.SED.changePIN(bandOwner, newKey, authAs, obj)
            if self.SED.checkPIN(bandOwner, newKey):
                print('Took ownership of {}'.format(bandOwner))
                self.keyManager.setKey(self.wwn, bandOwner, newKey)
            else:
                print('Failed to take ownership of {}'.format(bandOwner))

        elif self.SED.SSC == 'Opalv2':
            bandOwner = 'User{}'.format(bandNumber)
            
            auth = self.LockingSP
            authAs = (None, self.keyManager.getKey(self.wwn, self.LockingSP))
            obj = 'C_PIN_{}'.format(bandOwner)

            # Band needs to be activated first
            if self.SED.enableAuthority(self.LockingSP, True, bandOwner, authAs=(self.LockingSP, self.keyManager.getKey(self.wwn, self.LockingSP))):
                self.logger.debug('Enabled {}'.format(bandOwner))
            else:
                print('Failed to enable {}'.format(bandOwner))
                failureStatus = True

            # Take ownership
            newKey = self.keyManager.generateRandomValue()
            self.SED.changePIN(auth, newKey, authAs, obj)
            if self.SED.checkPIN(bandOwner, newKey):
                print('Took ownership of {}'.format(bandOwner))
                self.keyManager.setKey(self.wwn, bandOwner, newKey)
            else:
                print('Failed to take ownership of {}'.format(bandOwner))

        return failureStatus

    #********************************************************************************
    ##        name: printBandInfo
    #  description: Allows the user to configure a custom LBA band
    #   parameters:
    #               bandNumber - The band number to print info of
    #
    #       output:
    #               RangeStart - The starting LBA address of the band
    #                 RangeEnd - The ending LBA address of the band
    #              RangeLength - The length of the band
    #               ReadLocked - Indicates if the band is read locked
    #              WriteLocked - Indicates if the band is write locked
    #              LockOnReset - Indicates if the band will lock on reset
    #          ReadLockEnabled - Indicates if the band can be read locked
    #         WriteLockEnabled - Indicates if the band can be write locked
    #********************************************************************************
    def printBandInfo(self, bandNumber):
        if self.SED.SSC == 'Enterprise':
            user = 'BandMaster{}'.format(bandNumber)
            auth = ('EraseMaster', self.keyManager.getKey(self.wwn, 'EraseMaster'))
        else:
            user = 'Admin1'
            auth = ('Admin1', self.keyManager.getKey(self.wwn, 'Admin1'))

            if bandNumber == 0:
                print('Opalv2 does not support Global Range')
                return True

        info, rc = self.SED.getRange(bandNumber, user, auth)
        if bandNumber != 0:
            print('Band{} RangeStart       = 0x{:x}'.format(bandNumber, info.RangeStart))
            print('Band{} RangeEnd         = 0x{:x}'.format(bandNumber, info.RangeStart + info.RangeLength))
            print('Band{} RangeLength      = 0x{:x}'.format(bandNumber, info.RangeLength))
        print('Band{} ReadLocked       = {}'.format(bandNumber, ('unlocked','locked')[info.ReadLocked]))
        print('Band{} WriteLocked      = {}'.format(bandNumber, ('unlocked','locked')[info.WriteLocked]))
        print('Band{} LockOnReset      = {}'.format(bandNumber, info.LockOnReset))
        print('Band{} ReadLockEnabled  = {}'.format(bandNumber, ('False','True')[info.ReadLockEnabled]))
        print('Band{} WriteLockEnabled = {}'.format(bandNumber, ('False','True')[info.WriteLockEnabled]))
        return rc

    #********************************************************************************
    ##        name: configurePort
    #  description: configures the indicated port
    #   parameters:
    #               portname - The port to configure ('FWDownload' or 'UDS')
    #             lock_state - If true, lock the band. If false, unlock the band
    #    lock_on_reset_state - If true, enable lock-on-reset. If false, disable lock-on-reset
    #********************************************************************************
    def configurePort(self, portname, lock_state=True, lock_on_reset_state=True):
        if not self.keyManager.getKey( self.wwn, 'SID' ):
            print('Unable to access AdminSP - configurePort Failed')
            return False
        else:
            if self.SED.SSC == 'Enterprise' and portname == 'ActivationIEEE1667':
                print('ActivationIEEE1667 Port is not available on Enterprise')
                return False
            for uid in self.SED.ports.keys():
                port = self.SED.getPort(uid, authAs=('SID', self.keyManager.getKey(self.wwn, 'SID')))
                if port is not None and hasattr(port, 'Name') and port.Name == portname:
                    if self.SED.setPort(
                        uid,
                        PortLocked=lock_state,
                        LockOnReset=lock_on_reset_state,
                        authAs=('SID', self.keyManager.getKey(self.wwn, 'SID'))):
                            print('Sucessfully modified {} Port'.format(port.Name))
                            return True

    #********************************************************************************
    ##        name: lockPort
    #  description: Locks the indicated port
    #   parameters:
    #               portname - The port to lock/unlock ('FWDownload' or 'UDS')
    #             lock_state - If true, lock the port. If false, unlock the port
    #********************************************************************************
    def lockPort(self, portname):
        for uid in self.SED.ports.keys():
            port = self.SED.getPort(uid, authAs=('Anybody', None))
            if port is not None and hasattr(port, 'Name'):
                if port.Name == portname:
                    if port.PortLocked:
                        print('{} is already locked'.format(portname))
                        return True
        
        if self.configurePort(portname, True):
            print('Locked {}'.format(portname))
            return True
        else:
            print('Error Locking {}'.format(portname))
            return False

    #********************************************************************************
    ##        name: unlockPort
    #  description: unocks the indicated port
    #   parameters:
    #               portname - The port to unlock ('FWDownload' or 'UDS')
    #********************************************************************************
    def unlockPort(self, portname):
        for uid in self.SED.ports.keys():
            port = self.SED.getPort(uid, authAs=('Anybody', None))
            if port is not None and hasattr(port, 'Name'):
                if port.Name == portname:
                    if not port.PortLocked:
                        print('{} is already unlocked'.format(portname))
                        return True
        
        if self.configurePort(portname, False):
            print('Unlocked {}'.format(portname))
            return True
        else:
            print('Error Unlocking {}'.format(portname))
            return False

    #********************************************************************************
    ##        name: printPortStatus
    #  description: Prints the status of the UDS and FWDownload ports
    #********************************************************************************
    def printPortStatus(self):
        print('Port                Status       LockOnReset')
        for uid in self.SED.ports.keys():
            port = self.SED.getPort(uid, authAs=('Anybody', None))
            if port is not None and hasattr(port, 'Name'):
                print('{}{}{}{}{}'.format(
                    port.Name,                                                # Port Name
                    (20 - len(port.Name)) * ' ',                              # Whitespace padding
                    ('Unlocked','Locked')[port.PortLocked],                   # Port State
                    (13 - len(('Unlocked','Locked')[port.PortLocked])) * ' ', # Whitespace padding
                    ('Disabled','Enabled')[port.LockOnReset],                 # Lock on Reset State
                    ))

    #********************************************************************************
    ##        name: uploadJSONToVault
    #  description: Allows the user to upload a json credential file to Vault
    #********************************************************************************
    def uploadJSONToVault(self):
        jsonFilename = '{}.json'.format(self.wwn)
        with open(jsonFilename) as index:
            cred_table = json.load(index)
            for item in cred_table.keys():
                self.keyManager.setKey(self.wwn, item, cred_table[item])

    #********************************************************************************
    ##        name: enableFIPS
    #  description: Enable FIPS Mode by performing the following steps
    #               1) Disable Makers Authority
    #               2) Disable Firmware download
    #               3) Enable locking on all bands
    #               4) Opalv2 Only - Set minimum PIN length above 4
    #********************************************************************************
    def enableFIPS(self):
        if self.SED.checkPIN('SID', bytes(self.SED.mSID, encoding='utf8')) == True:
            print('Take ownership of drive before enabling FIPS')
            return False

        if not self.SED.fipsCompliance():
            print('Drive does not support FIPS')
            return False

        if not self.keyManager.getKey( self.wwn, 'SID' ):
            print('Unable to access AdminSP - enableFIPS Failed')
            return False

        # Disable Makers Authority
        if self.SED.enableAuthority(
            'SID', False, 'Makers', authAs=('SID', self.keyManager.getKey(self.wwn, 'SID'))) == False:
            print('Failed to disable Makers Authority')
            return False
        else:
            print('Disabled Makers Authority')

        # Disable Firmware Download
        if not self.lockPort('FWDownload'):
            return False

        if self.SED.SSC == 'Enterprise':
            # Check that all enabled bands are locked
            for bandNumber in self.keyManager.getBandNames(self.wwn):
                lockingInfo, status = self.SED.getRange(
                    int(bandNumber[10:]), 'EraseMaster', authAs=('EraseMaster', self.keyManager.getKey(self.wwn, 'EraseMaster')))
                if lockingInfo.ReadLockEnabled and lockingInfo.WriteLockEnabled:
                    print('{} Locking Enabled'.format(bandNumber))
                else:
                    print('{} Locking Disabled - enable before retrying enablefipsmode'.format(bandNumber))
                    return False

        elif self.SED.SSC == 'Opalv2':
            # Check that all enabled bands are locked
            for bandNumber in self.keyManager.getBandNames(self.wwn):
                lockingInfo, status = self.SED.getRange(
                    int(bandNumber[4:]), 'Admin1', authAs=('Admin1', self.keyManager.getKey(self.wwn, 'Admin1')))
                if lockingInfo.ReadLockEnabled and lockingInfo.WriteLockEnabled:
                    print('{} Locking Enabled'.format(bandNumber))
                else:
                    print('{} Locking Disabled - enable before retrying enablefipsmode'.format(bandNumber))
                    return False

            # Change MinPINlength for Opalv2
            self.authorities = {'SID': 'SID', 'Admin1': 'C_PIN_Admin1'}
            for user in self.keyManager.getBandNames(self.wwn):
                self.authorities[user] = 'C_PIN_{}'.format(user)
            for auth, auth_obj in self.authorities.items():
                if self.SED.setMinPINLength(auth, 4, authAs=(auth, self.keyManager.getKey(self.wwn, auth)), obj = auth_obj) is not True:
                    print('Failed to set MinPINlength for the authorities')
                    return False
                else:
                    print('Set min PIN length for {}'.format(auth))

        if self.SED.fipsApprovedMode==True:
            print('FIPS mode of the drive enabled successfully')
            return True
        else:
            print('Failed to enable FIPS mode')
            return False

    #********************************************************************************
    ##        name: TLSOperation
    #  description: Enable or Disable TLS Communication
    #********************************************************************************
    def TLSOperation(self, enable):
        if sys.platform == 'win32':
            print('TLS Support not provided for Windows')
            return False

        if self.SED.checkPIN('SID', bytes(self.SED.mSID, encoding='utf8')) == True:
            print('Take ownership of drive before modifying TLS state')
            return False

        if not self.keyManager.getKey( self.wwn, 'SID' ):
            print('Unable to access AdminSP - enableFIPS Failed')
            return False

        authAs = [
            (self.AdminSP, self.keyManager.getKey(self.wwn, self.AdminSP)),
            (self.LockingSP, self.keyManager.getKey(self.wwn, self.LockingSP))
            ]
        key = tcgSupport.getPsk(self.SED)
        if not key:
            print('Pre-Shared Key not generated')
            return False
        toUse = self.SED.getPskEntry(0)

        for entryID in range(4):
            psk = self.SED.getPskEntry(entryID)
            if not psk:
                print('Drive doesn\'t support TLS')
                return False
            
            if psk.Enabled and psk.CipherSuite == self.SED.cipherSuite:
                if enable:
                    print('TLS already enabled')
                    return True 
                else:
                    print('Disabling TLS - ', end='')
                    if self.SED.setPskEntry(toUse, authAs, Enabled=False, CipherSuite=self.SED.cipherSuite, PSK=key):
                        print('Successful')
                        return True
                    else:
                        print('Failed')
                        return False

            else:
                if enable:
                    print('Enabling TLS - ', end='')
                    if self.SED.setPskEntry(toUse, authAs, Enabled=True, CipherSuite=self.SED.cipherSuite, PSK=key):
                        print('Successful')
                        return True
                    else:
                        print('Failed')
                        return False

                else:
                    print('TLS already disabled')
                    return True

    #********************************************************************************
    def enableTLS(self):
        return self.TLSOperation( True )

    #********************************************************************************
    def disableTLS(self):
        return self.TLSOperation( False )

    #********************************************************************************
    ##        name: preDataStore
    #  description: Common steps for both Read and Write Datastore
    #********************************************************************************
    def preDataStore(self):
        # Check for Ownership
        if self.SED.checkPIN('SID', bytes(self.SED.mSID, encoding='utf8')) == True:
            print('Take ownership of drive before accessing SED DataStore')
            return False

        # Variables
        self.maxPayloadSize = 768
        self.SED.data_length = 1000 #Enough space to fit payload + extra

        # Make sure TLS is disabled
        for entryID in range(4):
            psk = self.SED.getPskEntry(entryID)
            if not psk:
                break
            if psk.Enabled and psk.CipherSuite == self.SED.cipherSuite:
                print('Please disable TLS')
                return False

        # Give Opal Read/Write access
        if self.SED.SSC == 'Opalv2':
            authAs = ('Admin1', self.keyManager.getKey(self.wwn, 'Admin1'))
            self.SED.readaccess('User1', 0, authAs)
            self.SED.writeaccess('User1', 0, authAs)

    #********************************************************************************
    ##        name: readDataStore
    #  description: Read the SED Datastore contents
    #               if --dataout is set at the command line,
    #               SED Datastore is written to file
    #********************************************************************************
    def readDataStore(self):
        self.preDataStore()
        authAs = (self.initialBandList[0], self.keyManager.getKey(self.wwn, self.initialBandList[0]))
        
        if self.opts.dataout:
            print('Reading SED DataStore and writing contents to {}'.format(self.opts.dataout))
        else:
            print('Reading SED DataStore')
        readData = self.SED.readData(self.initialBandList[0], authAs)
        if not readData:
            print('DataStore is empty')
        else:
            if self.opts.dataout:
                with open(self.opts.dataout, 'wb') as index:
                    index.write(readData['payload'])
            else:
                print(readData['payload'])

    #********************************************************************************
    ##        name: writeDataStore
    #  description: Write the contents of --infile to the SED Datastore
    #********************************************************************************
    def writeDataStore(self):
        self.preDataStore()
        authAs = (self.initialBandList[0], self.keyManager.getKey(self.wwn, self.initialBandList[0]))

        print('Writing contents of {} to SED DataStore'.format(self.opts.datain))
        if os.path.getsize(self.opts.datain) > self.maxPayloadSize:
            print('File {} is larger than maximum allowed size of {} bytes'.format(self.opts.datain, self.maxPayloadSize))
            return False
        with open(self.opts.datain, 'rb') as index:
            data = dict()
            data['iv'] = uuid.uuid4().bytes
            data['payload'] = index.read()
            self.SED.data_length = len(tcgSupport.serialize(data))
            if self.SED.writeData(self.initialBandList[0], data, authAs):
                print('Write Successful')
                return True
            else:
                print('Write Failed, payload/file may be too large')
                return True

    #********************************************************************************
    ##        name: isOwned
    #  description: Returns True if drive is Owned, False if not
    #********************************************************************************
    def isOwned(self):
        return self.SED.checkPIN(self.AdminSP, self.initial_cred) != True

    #********************************************************************************
    #         name: validateSeagateCert
    #  description: Validates that the Drive's certificate was signed by Seagate
    #********************************************************************************
    def validateSeagateCert(self):
        if self.SED.fipsCompliance():
            print('Drive Cert     = N/A (FIPS Configuration)')
            return False

        deviceCert = self.SED.get_tperSign_cert()

        # Validate the drive cert against the Seagate root cert
        identity = verifyIdentity.VerifyIdentity(deviceCert)
        identity.validate_drive_cert()

        # Validate device signature by signing a dummy payload
        timestamp = str(datetime.datetime.today())
        signature = self.SED.tperSign(bytes(timestamp, encoding='utf8'))

        # Compare signatures
        if identity.validate_signature(timestamp, signature):
            print('Drive Cert     = Authentic Seagate Device')
            return True
        else:
            print('Drive Cert     = Unable to Authenticate')
            return False

    #********************************************************************************
    #         name: fwAttestation
    #  description: Enables Seagate Proprietary FW Attestation feature.  Includes the following:
    # 
    # **Assessor Nonce:** A random 128 bit value generated by the Assessor (Host)
    # **Root of Trust Reporting ID:** The Common Name derived from the subject name in Tper Attestation Certificate 
    #   encoded in DER format (GUDID) The firmware_attestation method will fail if the RTR ID does not match
    # **Assessor ID:** A random value generated by the host, which will be included in the Signed Attestation Message 
    #
    # Hashes of the Measurment data which comprises of the following is generated and printed:
    # - Boot firmware 1 measurement value
    # - Boot firmware 2 measurement value
    # - Servo firmware measurement value
    # - Controller firmware measurement value
    # - Security firmware measurement value
    #********************************************************************************
    def fwAttestation(self):
        print()
        print("*** THIS IS THE FW ATTEST METHOD. IT IS A SEAGATE PROPRIETARY METHOD AND WORKS ONLY WITH SEAGATE DEVICES ***")
        print()

        # Retrieve the Tper attestation certificate
        att_cert = self.SED.get_tperAttestation_Cert()
        if (len(att_cert)) == 0:
            print("The drive does not contain an attestation certificate")
            return

        # Validate the drive attestation certificate against the root certificate
        identity = verifyIdentity.VerifyIdentity(att_cert)
        identity.validate_drive_cert()

        # Simulated values for the assessor_nonce, assessor_ID, sub_name
        (assessor_nonce, sub_name) = ('23helloseagate', identity.CN)
        assessor_ID = '34254525432Seagate'

        # Receive Firmware attestation message from the drive
        self.logger.debug('Get FW attestation meassge')
        ret = self.SED.firmware_attestation(assessor_nonce, sub_name, assessor_ID)

        # Verify the signature with the original string
        if (ret):
            return_val = ret[0]
            (Assessor_Nonce, Measurement, data, signature) = (tcgSupport.convert(return_val[512:528].replace(b'\x00',b'')), return_val[528:1376].hex(), return_val[0:1376], return_val[1376:1760])
            if (Assessor_Nonce != assessor_nonce):
                return False
            if (sub_name and assessor_ID):
                (Assessor_ID, RTR_ID) = (tcgSupport.convert(return_val[0:256].replace(b'\x00',b'')), tcgSupport.convert(return_val[256:512].replace(b'\x00',b'')))
                if (Assessor_ID != assessor_ID and RTR_ID != sub_name):
                    return False
            
            # Display the measurement data to customers for verification
            if identity.validate_signature(data, signature) == True:
                print('The measurement data fields are displayed below:\n')
                print('Secure Boot Process Device state={}\nSigning Authority Database={}\nSigning Authority Key Certificate Hash={}\nSee Signing Authority Key Certificate Hash={}\nBFW ITCM Hash={}\nBFW IDBA Hash={}\nServo FW Hash={}\nCFW Hash={}\nSEE FW Hash={}\n'.format(Measurement[3:131],Measurement[131:351],Measurement[351:383],Measurement[383:415],Measurement[415:447],Measurement[447:479],Measurement[479:511],Measurement[511:543],Measurement[543:575]))
                return True

        return False

    #********************************************************************************
    #         name: unittest
    #  description: Runs a sequence of commands, in order to validate all functionality
    #********************************************************************************
    def unittest(self):
        timeToWait = 15
        while timeToWait > 0:
            print('')
            print('UNIT TEST will commence in {} seconds'.format(timeToWait))
            print('    ALL Data on {} will be DESTROYED'.format(self.opts.device, self.opts.bandno))
            print('        Press control-C to abort')
            time.sleep(5)
            timeToWait -= 5

        # Vars
        bandno = 7
        rangestart = 0x1000
        rangelength = 0x1000
        port = 'UDS'

        print("\n### Revert Drive")
        self.revertDrive()

        print("\n### Print Drive Info")
        self.printDriveInfo()

        print("\n### Take Ownership")
        self.takeOwnership()

        print("\n### Give Up Ownership")
        self.giveUpOwnership()

        print("\n### Retake Ownership")
        self.takeOwnership()

        print("\n### Rotate Keys")
        self.rotateLockingSP()
        self.rotateAdminSP()
        
        print("\n### Configure Band")
        self.configureBands(bandno, rangestart, rangelength, lock_state=False, lock_on_reset_state=True)

        print("\n### Lock/Unlock Band")
        self.lockBand(bandno)
        self.printBandInfo(bandno)
        self.unlockBand(bandno)
        self.printBandInfo(bandno)

        print("\n### Erase Band")
        self.eraseBand(bandno)

        print("\n### Configure Port")
        self.configurePort(port, lock_state=False, lock_on_reset_state=True)
        self.printPortStatus()

        print("\n### Lock/Unlock Port")
        self.lockPort(port)
        self.printPortStatus()
        self.unlockPort(port)
        self.printPortStatus()

        print("\n### Enable FIPS")
        if self.SED.SSC == 'Enterprise':
            self.configureBands(0)
        self.configureBands(1, 0x0, 0x1000)
        self.enableFIPS()

        print("\n### Write Datastore")
        test_file = 'datastoretest.txt'
        test_read = 'datastoreread.txt'
        with open(test_file, 'w') as index:
            index.write(self.keyManager.generateRandomValue())
        self.opts.datain = test_file
        self.writeDataStore()

        self.opts.dataout = ''
        self.readDataStore()

        self.opts.dataout = test_read
        self.readDataStore()
        if filecmp.cmp(test_file, test_read):
            print('Files are equal')
        else:
            print('Files are NOT equal')

        if os.path.exists(test_file):
            os.remove(test_file)
        if os.path.exists(test_read):
            os.remove(test_read)

        print("\n### Enable/Disable TLS")
        self.enableTLS()
        self.disableTLS()

#***********************************************************************************************************************
# tperSign
#***********************************************************************************************************************
def main(arguments):
    opts = parse_args()

    # Create the SEDConfig class
    SEDConfig = cSEDConfig(opts.device, opts.keymanager, opts)

    if opts.operation == 'configureband':
        if not SEDConfig.configureBands(opts.bandno, opts.rangestart, opts.rangelength, lock_state=False, lock_on_reset_state=opts.lockonreset):
            SEDConfig.printBandInfo(opts.bandno)
        pass

    if opts.operation == 'configureport':
        SEDConfig.configurePort(opts.port, lock_state=False, lock_on_reset_state=opts.lockonreset)
        SEDConfig.printPortStatus()
        pass

    if opts.operation == 'disabletls':
        SEDConfig.disableTLS()
        pass

    if opts.operation == 'enabletls':
        SEDConfig.enableTLS()
        pass

    if opts.operation == 'enablefipsmode':
        SEDConfig.enableFIPS()
        pass

    if opts.operation == 'eraseband':
        SEDConfig.printBandInfo(opts.bandno)
        timeToWait = 15
        while timeToWait > 0:
            print('')
            print('BAND ERASE will commence in {} seconds'.format(timeToWait))
            print('    ALL Data on {} band{} will be DESTROYED'.format(opts.device, opts.bandno))
            print('        Press control-C to abort')
            time.sleep(5)
            timeToWait -= 5
        
        print('')
        print('Band Erase has started')
        SEDConfig.eraseBand(opts.bandno)
        pass

    if opts.operation == 'fwattestation':
        SEDConfig.fwAttestation()
        pass

    if opts.operation == 'giveupownership':
        SEDConfig.giveUpOwnership()
        pass

    if opts.operation == 'lockband':
        SEDConfig.lockBand(opts.bandno)
        SEDConfig.printBandInfo(opts.bandno)
        pass

    if opts.operation == 'lockport':
        SEDConfig.lockPort(opts.port)
        SEDConfig.printPortStatus()
        pass

    if opts.operation == 'printbandinfo':
        SEDConfig.printBandInfo(opts.bandno)
        pass

    if opts.operation == 'printdriveinfo':
        SEDConfig.printDriveInfo()
        print('')
        SEDConfig.printPortStatus()
        pass

    if opts.operation == 'readdatastore':
        SEDConfig.readDataStore()
        pass

    if opts.operation == 'revertdrive':
        timeToWait = 15
        while timeToWait > 0:
            print('')
            print('REVERT SP will commence in {} seconds'.format(timeToWait))
            print('    ALL Data on {} will be DESTROYED'.format(opts.device, opts.bandno))
            print('        Press control-C to abort')
            time.sleep(5)
            timeToWait -= 5
        SEDConfig.revertDrive()
        pass

    if opts.operation == 'rotateadminsp':
        SEDConfig.rotateAdminSP()
        pass

    if opts.operation == 'rotatelockingsp':
        SEDConfig.rotateLockingSP()
        pass

    if opts.operation == 'takeownership':
        SEDConfig.takeOwnership()
        pass

    if opts.operation == 'unlockband':
        SEDConfig.unlockBand(opts.bandno)
        SEDConfig.printBandInfo(opts.bandno)
        pass

    if opts.operation == 'unlockport':
        SEDConfig.unlockPort(opts.port)
        SEDConfig.printPortStatus()
        pass

    if opts.operation == 'validateseagate':
        SEDConfig.validateSeagateCert()
        pass

    if opts.operation == 'writedatastore':
        SEDConfig.writeDataStore()
        pass

    if opts.operation == 'unittest':
        SEDConfig.unittest()
        pass

# ****************************************************************************
if __name__ == '__main__':
    main(sys.argv)