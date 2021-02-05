import argparse
import datetime
import json
import logging
import os
import sys
import time
import uuid

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
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter)

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

    parser.add_argument('--lockonreset', type=str2bool,
                        help='Enable/Disable lock on reset')

    parser.add_argument('--logfile', default='sedcfg.log',
                        help='The filename of the logfile to write')

    parser.add_argument('--port', choices=('UDS', 'FWDownload', 'ActivationIEEE1667'),
                        help='The port to lock or unlock')

    parser.add_argument('--psid', default=None,
                        help='The PSID of the drive, used for factory restore, found on drive label')

    parser.add_argument('--rangestart', default=None, type=auto_int,
                        help='The LBA to start the band at')

    parser.add_argument('--rangelength', default=None, type=auto_int,
                        help='The length of the band')

    parser.add_argument('--skipcert', action='store_true', default=False,
                        help='Skip validation of the drive certificate')

    parser.add_argument('--vaultconfig', default='vaultcfg.json',
                        help='The filename of the vault config file')

    parser.add_argument('--operation', default='printdriveinfo', choices=(
        'addband',
        'configureband',
        'configureport',
        'disabletls',
        'enablefipsmode',
        'enabletls',
        'giveupownership',
        'eraseband',
        'lockband',
        'lockport',
        'printbandinfo',
        'printdriveinfo',
        'readdatastore',
        'removeband',
        'revertdrive',
        'rotatekeys',
        'takeownership',
        'unlockband',
        'unlockport',
        'writedatastore',
    ))

    opts = parser.parse_args()

    if opts.operation == 'revertdrive' and not opts.psid:
        parser.error('--psid argument is mandatory for the revertdrive operation')

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

        # Test the KeyManager to ensure read/write access
        randomName = str(self.keyManager.generateRandomValue())
        randomKey = self.keyManager.generateRandomValue()
        randomValue = self.keyManager.generateRandomValue()

        if self.keyManager.setKey(randomName, randomKey, randomValue):
            print('Unable to interface with keymanager - exiting script')
            sys.exit(1)

        if self.keyManager.getKey(randomName, randomKey) != randomValue:
            print('Unable to interface with keymanager - exiting script')
            sys.exit(1)

        if self.keyManager.deletePasswords(randomName):
            print('Unable to interface with keymanager - exiting script')
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
        
        if not self.opts.skipcert:
            self.validateSeagateDrive()
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
                    print('Enabled {}'.format(bandOwner))
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
    ##        name: rotateKeys
    #  description: Retrieves the password of each user from the KeyManager,
    #               changes the password of each user on the drive,
    #               saves the updated passwords to the KeyManager
    #********************************************************************************
    def rotateKeys(self, giveUpOwnership = False):

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

            # If giving up ownership on Opalv2, bands needs to be disabled
            if self.SED.SSC == 'Opalv2' and giveUpOwnership:
                if self.SED.enableAuthority(self.LockingSP, False, bandOwner, authAs=(self.LockingSP, self.keyManager.getKey(self.wwn, self.LockingSP))):
                    print('Disabled {}'.format(bandOwner))
                else:
                    print('Failed to disable {}'.format(bandOwner))
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

    #********************************************************************************
    #  description: Gives up ownership of a drive by resetting credentials to default
    #               Note - this method RETAINS USER DATA
    #********************************************************************************
    def giveUpOwnership(self):
        failureStatus = False

        if not self.rotateKeys(giveUpOwnership=True):
            # Unlock Ports
            self.configurePort('UDS', False, False)
            self.configurePort('FWDownload', False, False)
            if self.SED.SSC == 'Opalv2':
                self.configurePort('ActivationIEEE1667', False, False)
            self.keyManager.deletePasswords(self.wwn)
        else:
            print('Failed to give up ownership')
            failureStatus = True

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
            if bandNumber > 1:
                print('Enterprise does not yet support bands 2-15')
                return True
            elif auth not in self.keyManager.getBandNames(self.wwn):
                # Add band, if it hasn't been enabled yet
                self.addBand(bandNumber)
        else:
            auth = 'Admin1'
            if bandNumber == 0:
                print('Opalv2 does not support Global Range')
                return True
            elif 'User{}'.format(bandNumber) not in self.keyManager.getBandNames(self.wwn):
                # Add band, if it hasn't been enabled yet
                self.addBand(bandNumber)

        if bandNumber == '0' and rangeStart != None:
            print('Can\'t change range for global locking range')
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
                print('Locked Band{}'.format(bandNumber))
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
    #   parameters:
    #               bandNumber - The band to erase
    #********************************************************************************
    def eraseBand(self, bandNumber):
        if self.SED.SSC == 'Enterprise':
            user = 'BandMaster{}'.format(bandNumber)
            if self.SED.erase(bandNumber, authAs=('EraseMaster', self.keyManager.getKey(self.wwn, 'EraseMaster'))):
                print('Band{} sucessfully erased'.format(bandNumber))
                
                # In Enterprise, band erasure will revert ownership, so delete the band from the key list
                self.keyManager.deleteKey(self.wwn, user)

                # Then readd
                self.addBand(bandNumber)
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
    def addBand(self, bandNumber):
        failureStatus = False

        if self.SED.checkPIN('SID', bytes(self.SED.mSID, encoding='utf8')) == True:
            print('Take ownership of drive before adding a band')
            return True

        if self.SED.SSC == 'Enterprise':
            if bandNumber > 1:
                print('Bands 2-15 are not yet supported')
                failureStatus = True
                return failureStatus

            newKey = self.keyManager.generateRandomValue()

            # Setup variables for each config
            bandOwner = 'BandMaster{}'.format(bandNumber)
            authAs = (None, self.initial_cred)
            obj = None

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
                print('Enabled {}'.format(bandOwner))
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
    def removeBand(self, bandNumber):
        failureStatus = False
        if self.SED.SSC == 'Enterprise':
            print('Band Removal is not yet supported on Enerprise Configs')
            failureStatus = True
            return failureStatus

        elif self.SED.SSC == 'Opalv2':
            bandOwner = 'User{}'.format(bandNumber)
            if bandOwner not in self.keyManager.getBandNames(self.wwn):
                print('{} is not currently enabled'.format(bandOwner))
                failureStatus = True
                return failureStatus
            else:
                self.keyManager.deleteKey(bandOwner)

            # Setup variables for each config
            auth = self.LockingSP
            authAs = (None, self.keyManager.getKey(self.wwn, self.LockingSP))
            obj = 'C_PIN_{}'.format(bandOwner)
            
            # Take ownership
            newKey = self.initial_cred
            self.SED.changePIN(auth, newKey, authAs, obj)
            if self.SED.checkPIN(bandOwner, newKey):
                print('Gave up {}'.format(bandOwner))
                self.keyManager.setKey(self.wwn, bandOwner, newKey)
            else:
                print('Failed to give up {}'.format(bandOwner))

            # Band needs to be disabled
            if self.SED.enableAuthority(self.LockingSP, False, bandOwner, authAs=(self.LockingSP, self.keyManager.getKey(self.wwn, self.LockingSP))):
                print('Disabled {}'.format(bandOwner))
            else:
                print('Failed to disable {}'.format(bandOwner))
                failureStatus = True

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
        return self.configurePort(portname, True)

    #********************************************************************************
    ##        name: unlockPort
    #  description: unocks the indicated port
    #   parameters:
    #               portname - The port to unlock ('FWDownload' or 'UDS')
    #********************************************************************************
    def unlockPort(self, portname):
        return self.configurePort(portname, False)

    #********************************************************************************
    ##        name: printPortStatus
    #  description: Prints the status of the UDS and FWDownload ports
    #********************************************************************************
    def printPortStatus(self):
        print('Port                Status       LockOnReset')
        for uid in self.SED.ports.keys():
            # If default cred, use them, else look up via keymanager
            if self.SED.checkPIN('SID', bytes(self.SED.mSID, encoding='utf8')) == True:
                port = self.SED.getPort(uid, authAs=('SID', bytes(self.SED.mSID, encoding='utf8')))
            else:
                port = self.SED.getPort(uid, authAs=('SID', self.keyManager.getKey(self.wwn, 'SID')))
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
        self.keyManager.storePasswords(self.wwn, cred_table)

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

        # Disable Makers Authority
        if self.SED.enableAuthority(
            'SID', False, 'Makers', authAs=('SID', self.keyManager.getKey(self.wwn, 'SID'))) == False:
            print('Failed to disable Makers Authority')
            return False
        else:
            print('Disabled Makers Authority')

        # Disable Firmware Download
        if not self.lockPort('FWDownload'):
            print('Failed to disable FWDownload')
            return False
        else:
            print('Disabled FWDownload')

        if self.SED.SSC == 'Enterprise':
            # Check that all enabled bands are locked
            for bandNumber in self.keyManager.getBandNames(self.wwn):
                lockingInfo, status = self.SED.getRange(
                    int(bandNumber[10:]), 'EraseMaster', authAs=('EraseMaster', self.keyManager.getKey(self.wwn, 'EraseMaster')))
                if lockingInfo.ReadLockEnabled and lockingInfo.WriteLockEnabled:
                    print('Band{} Locking Enabled'.format(bandNumber))
                else:
                    print('Band{} Locking Disabled - enable before retrying enablefipsmode'.format(bandNumber))
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
    def validateSeagateDrive(self):
        if self.SED.fipsCompliance():
            print('Drive Cert     = N/A (FIPS Configuration)')
            return False

        deviceCert = self.SED.get_tperSign_cert()

        # Validate the drive cert against the Seagate root cert
        identity = verifyIdentity.VerifyIdentity(deviceCert, self.logger)
        identity.validate_drive_cert()

        # Validate device signature by signing a dummy payload
        timestamp = str(datetime.datetime.today())
        signature = self.SED.tperSign(bytes(timestamp, encoding='utf8'))

        # Compare signatures
        if identity.validate_signature(timestamp, signature):
            print('Drive Cert     = Authentic Seagate Device')
            return True
        else:
            print('Drive Cert     = Non-Seagate Device')
            return False

#***********************************************************************************************************************
# tperSign
#***********************************************************************************************************************
def main(arguments):
    opts = parse_args()

    # Create the SEDConfig class
    SEDConfig = cSEDConfig(opts.device, opts.keymanager, opts)

    # 'Switch' statement on operation
    if opts.operation == 'addband':
        SEDConfig.addBand(opts.bandno)
        pass

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

    if opts.operation == 'removeband':
        SEDConfig.removeBand(opts.bandno)
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

    if opts.operation == 'rotatekeys':
        SEDConfig.rotateKeys()
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

    if opts.operation == 'writedatastore':
        SEDConfig.writeDataStore()
        pass

# ****************************************************************************
if __name__ == '__main__':
    main(sys.argv)