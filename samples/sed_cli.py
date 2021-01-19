#-----------------------------------------------------------------------------
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

import argparse
import json
import logging
import os
import sys
import time
from enum import Enum

## Add TCGstorageAPI path
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))

from TCGstorageAPI.tcgapi import Sed as SED
from keymanager import keymanager_vault
from keymanager import keymanager_json

def auto_int(x):
    return int(x, 0)

def parse_args():
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('--bandno', default=0, type=int,
                        help='The band to operate on')

    parser.add_argument('--vaultconfig', default='vaultcfg.json',
                        help='The filename of the vault config file')

    parser.add_argument('--device', default=None,
                        help='The OS path to the device under operation')

    parser.add_argument('--keymanager', default='vault',
                        help='The keymanager to use')

    parser.add_argument('--lockonreset', action='store_true', default=False,
                        help='Enable/Disable lock on reset')

    parser.add_argument('--logfile', default="sedcfg.log",
                        help='The filename of the logfile to write')

    parser.add_argument('--port', choices=('UDS', 'FWDownload'),
                        help='The port to lock or unlock')

    parser.add_argument('--psid', default=None,
                        help='The PSID of the drive, used for factory restore, found on drive label')

    parser.add_argument('--rangestart', default=None, type=auto_int,
                        help='The LBA to start the band at')

    parser.add_argument('--rangelength', default=None, type=auto_int,
                        help='The length of the band')

    parser.add_argument('--operation', default='printdriveinfo', choices=(
        'configureband',
        'configureport',
        'enablefipsmode',
        'giveupownership',
        'eraseband',
        'lockband',
        'lockport',
        'printbandinfo',
        'printdriveinfo',
        'revertdrive',
        'rotatekeys',
        'takeownership',
        'unlockband',
        'unlockport',
    ))

    opts = parser.parse_args()

    if opts.operation == "revertdrive" and not opts.psid:
        parser.error('--psid argument is mandatory for the revertdrive operation')

    if not opts.device:
        parser.error('--device argument is mandatory')

    if opts.keymanager == 'json':
        opts.keymanager = keyManagerType.JSON
    else:
        opts.keymanager = keyManagerType.VAULT

    return opts

## 
class keyManagerType(Enum):
    JSON = 1
    VAULT = 2

#***********************************************************************************************************************
## cSEDConfig
#
#  This is a class for performing operations on the SED drive
#
#  Attributes:
#    deviceHandle: Device Handle of drive (ex: /dev/sdb)
#    KeyManagerType: Value indicating which KeyManager type to use
#    opts: The argparse object
#***********************************************************************************************************************
class cSEDConfig(object):
    def __init__(self, deviceHandle, KeyManagerType, opts):

        ## Initialize Class Variables
        self.opts = opts
        self.log_filename = self.opts.logfile
        self.deviceHandle = deviceHandle
        self.driveType = None

        ## Initialize Logger
        logging.basicConfig(
            filename=self.log_filename,
            format="%(asctime)s %(name)s (%(threadName)s) - %(message)s",
            level=logging.DEBUG)
        self.logger = logging.getLogger(self.log_filename)

        ## Initialize KeyManager
        if KeyManagerType == keyManagerType.VAULT:  ## Vault KeyManager
            self.keyManager = keymanager_vault.keymanager_vault(self.opts.vaultconfig)

        elif KeyManagerType == keyManagerType.JSON: ## JSON KeyManager
            self.keyManager = keymanager_json.keymanager_json()
        else:
            print("Unknown KeyManager Type!")
            sys.exit(1)

        # Test the KeyManager to ensure read/write access
        randomName = str(self.keyManager.generateRandomValue())
        randomKey = self.keyManager.generateRandomValue()
        randomValue = self.keyManager.generateRandomValue()

        if self.keyManager.setKey(randomName, randomKey, randomValue):
            print("Unable to interface with keymanager - exiting script")
            sys.exit(1)

        if self.keyManager.getKey(randomName, randomKey) != randomValue:
            print("Unable to interface with keymanager - exiting script")
            sys.exit(1)

        if self.keyManager.deletePasswords(randomName):
            print("Unable to interface with keymanager - exiting script")
            sys.exit(1)

        ## Initialize the SED object
        self.SED = SED(self.deviceHandle, callbacks=self)
        
        ## Get the WWN in string format
        self.wwn = format(self.SED.wwn, 'X')
        
        ## Initialize the mSID
        self.initial_cred = self.SED.mSID

        ## Check Security Type
        if self.SED.SSC == "Enterprise":
            self.logger.info("SED configuration is Enterprise")
        elif self.SED.SSC == "Opalv2":
            self.logger.info("SED configuration is Opalv2")
        else:
            print("SED configuration is Unknown/Unsupported (Type {}) - Exiting Script".format(self.SED.SSC))
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
        print("Drive Handle   = {}".format(self.deviceHandle))
        if self.SED.fipsCompliance():
            print("Model Number   = {}".format(self.SED.fipsCompliance()['hardwareVersion']))
            print("FW Revision    = {}".format(self.SED.fipsCompliance()['descriptorVersion']))
            print("FIPS Compliant = {}".format(self.SED.fipsApprovedMode))
        print("WWN            = {:X}".format(self.SED.wwn))
        print("MSID           = {}".format(self.SED.mSID))
        print("MaxLBA         = 0x{:X}".format(self.SED.maxLba))
        print("Is Owned       = {}".format(self.isOwned()))
        print("Is Locked      = {}".format(self.SED.hasLockedRange))

    #********************************************************************************
    ##        name: printSecurityInfo
    #  description: Prints various information about the drive's state to console
    #********************************************************************************
    def printSecurityInfo(self):
        SEDInfo = self.SED.lockingInfo()
        print("Max Ranges = {}".format(SEDInfo.MaxRanges))
        print("Encryption Support = {}".format(SEDInfo.EncryptSupport))
        print("BlockSize = {}".format(SEDInfo.LogicalBlockSize))
        print("LowestAlignedLBA = {}".format(SEDInfo.LowestAlignedLBA))
        print("AlignmentGranularity = {}".format(SEDInfo.AlignmentGranularity))
        print("AlignmentRequired = {}".format(SEDInfo.AlignmentRequired))
        print("MaxReEncryptions = {}".format(SEDInfo.MaxReEncryptions))
        print("KeysAvailableCfg = {}".format(SEDInfo.KeysAvailableCfg))

    #********************************************************************************
    ##        name: takeOwnership
    #  description: Takes ownership of a drive by replacing the initial credentials
    #               with unique values, which are saved to the KeyManager
    #********************************************************************************
    def takeOwnership(self, userList):
        failureStatus = False

        ## Update each credential
        for user in userList:
            newValue = self.keyManager.generateRandomValue()
            if self.SED.checkPIN( user, bytes(self.SED.mSID, encoding='utf8')) == True:
                self.SED.changePIN(user, newValue, (None, self.initial_cred))
                if self.SED.checkPIN(user, newValue):
                    print("Took ownership of {}".format(user))
                    self.keyManager.setKey(self.wwn, user, newValue)
                else:
                    print("Failed to take ownership of {}".format(user))
                    failureStatus = True
            else:
                print("Ownership of {} already taken".format(user))

        # If Opal, do additional steps
        if self.SED.SSC == "Opalv2":
            newValue = self.keyManager.generateRandomValue()
            if self.SED.activate("SID"):
                failureStatus = True
            if self.SED.changePIN("Admin1", newValue, (None, self.initial_cred), C_PIN_Admin1):
                failureStatus = True

            self.enable_authority()

        return failureStatus

    #********************************************************************************
    #  description: Gives up ownership of a drive by resetting credentials to default
    #               Note - this method RETAINS USER DATA
    #********************************************************************************
    def giveUpOwnership(self):
        failureStatus = False

        # Check if WWN is in keymanager, if not, exit
        if self.wwn not in self.keyManager.getWWNs():
            print("WWN {} not in KeyManager".format(self.wwn))
            failureStatus = True
        else:
            ## Update each credential
            cred_table = self.keyManager.getPasswords(self.wwn)
            for user in cred_table.keys():
                if cred_table[user]:
                    if not self.SED.checkPIN( user, (user, self.keyManager.getKey(self.wwn, user))):
                        newValue = self.initial_cred
                        self.SED.changePIN( user, newValue, (user, self.keyManager.getKey(self.wwn, user)))
                        if self.SED.checkPIN( user, newValue ):
                            print("Successfully Gave Up {}".format(user))
                            self.keyManager.setKey(self.wwn, user, newValue)
                        else:
                            print("Error Updating {}".format(user))
                            failureStatus = True
                    else:
                        print("Password for {} in KeyManager is incorrect! Fix or RevertSP".format(user))
                        failureStatus = True

            # Unlock Ports
            self.configurePort("UDS", False, False)
            self.configurePort("FWDownload", False, False)
        return failureStatus

    #********************************************************************************
    ##        name: rotateKeys
    #  description: Retrieves the password of each user from the KeyManager,
    #               changes the password of each user on the drive,
    #               saves the updated passwords to the KeyManager
    #********************************************************************************
    def rotateKeys(self):
        failureStatus = False

        # Check if WWN is in keymanager, if not, exit
        if self.wwn not in self.keyManager.getWWNs():
            print("WWN {} not in KeyManager".format(self.wwn))
            failureStatus = True
        else:
            cred_table = self.keyManager.getPasswords(self.wwn)
            for user in cred_table.keys():
                if cred_table[user]:
                    newValue = self.keyManager.generateRandomValue()

                    # Before attempting to update the password, validate the current one, if incorrect, exit
                    if not self.SED.checkPIN( user, self.keyManager.getKey(self.wwn, user) ):
                        print("Password for {} in KeyManager is incorrect! Fix or RevertSP".format(user))
                        failureStatus = True

                    # Change password, validate new password, update keymanager
                    else:
                        self.SED.changePIN( user, newValue, (user, self.keyManager.getKey(self.wwn, user)))
                        if self.SED.checkPIN( user, newValue ):
                            print("Successfully Updated {}".format(user))
                            self.keyManager.setKey(self.wwn, user, newValue)
                        else:
                            print("Error Updating {}".format(user))
                            failureStatus = True
        return failureStatus

    #********************************************************************************
    ##        name: configureBands
    #  description: Allows the user to configure a custom LBA band
    #   parameters:
    #               bandNumber - The band number to configure
    #               rangeStart - The LBA to start at
    #              rangeLength - The Length of the desired LBA band
    #               lock_state - Lock the Band
    #      lock_on_reset_state - Indicate if the band should lock on reset
    #********************************************************************************
    def configureBands(self, bandNumber, rangeStart=None, rangeLength=None, lock_state=False, lock_on_reset_state=True):
        self.logger.debug("Configuring bands on the drive")
        if self.SED.checkPIN("SID", bytes(self.SED.mSID, encoding='utf8')) == True:
            print("Take ownership of drive before configuring")
            return False

        ## Configure Band
        user = "BandMaster{}".format(bandNumber)
        configureStatus = self.SED.setRange(
            user,
            int(bandNumber),
            authAs=(user, self.keyManager.getKey(self.wwn, user)),
            RangeStart=int(rangeStart) if rangeStart is not None else None,
            RangeLength=int(rangeLength) if rangeStart is not None else None,
            ReadLockEnabled=1,
            WriteLockEnabled=1,
            LockOnReset=lock_on_reset_state,
            ReadLocked=lock_state,
            WriteLocked=lock_state,
            )
        
        if configureStatus:
            print("Band{} is configured".format(bandNumber))
            return True
        else:
            print("Error configuring Band{}".format(bandNumber))
            return False

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
        user = "BandMaster{}".format(bandNumber)
        info, rc = self.SED.getRange(
            bandNumber,
            user,
            authAs=("EraseMaster", self.keyManager.getKey(self.wwn, "EraseMaster")))
        print("Band{} RangeStart       = 0x{:x}".format(bandNumber, info.RangeStart))
        print("Band{} RangeEnd         = 0x{:x}".format(bandNumber, info.RangeStart + info.RangeLength))
        print("Band{} RangeLength      = 0x{:x}".format(bandNumber, info.RangeLength))
        print("Band{} ReadLocked       = {}".format(bandNumber, ("unlocked","locked")[info.ReadLocked]))
        print("Band{} WriteLocked      = {}".format(bandNumber, ("unlocked","locked")[info.WriteLocked]))
        print("Band{} LockOnReset      = {}".format(bandNumber, info.LockOnReset))
        print("Band{} ReadLockEnabled  = {}".format(bandNumber, ("False","True")[info.ReadLockEnabled]))
        print("Band{} WriteLockEnabled = {}".format(bandNumber, ("False","True")[info.WriteLockEnabled]))
        return rc

    #********************************************************************************
    ##        name: lockBand
    #  description: Allows the user to lock/unlock the indicated band
    #   parameters:
    #               bandNumber - The band to lock/unlock
    #               lock_state - If true, lock the band. If false, unlock the band
    #********************************************************************************
    def lockBand(self, bandNumber):
        return self.configureBands(bandNumber, lock_state=True)

    #********************************************************************************
    ##        name: unlockBand
    #  description: Allows the user to unlock the indicated band
    #   parameters:
    #               bandNumber - The band to unlock
    #********************************************************************************
    def unlockBand(self, bandNumber):
        return self.configureBands(bandNumber, lock_state=False)

    #********************************************************************************
    ##        name: eraseBand
    #  description: Allows the user to erase the indicated band
    #   parameters:
    #               bandNumber - The band to erase
    #********************************************************************************
    def eraseBand(self, bandNumber):
        user = "BandMaster{}".format(bandNumber)
        if self.SED.erase(bandNumber, authAs=("EraseMaster", self.keyManager.getKey(self.wwn, "EraseMaster"))):
            print("Band{} sucessfully erased".format(bandNumber))
            return True
        else:
            print("Error - Band{} was not erased".format(bandNumber))
            return False

    #********************************************************************************
    ##        name: revertDrive
    #  description: Allows the user to revert the drive to factory settings
    #********************************************************************************
    def revertDrive(self):
        if self.SED.revert(self.opts.psid):
            print("Drive succesfully erased and reverted to factoring settings")
            return True
        else:
            print("Drive was not erased, check that the PSID is correct")
            print("Entered PSID - \"{}\"".format(self.opts.psid))
            return False

    #********************************************************************************
    ##        name: printPortStatus
    #  description: Prints the status of the UDS and FWDownload ports
    #********************************************************************************
    def printPortStatus(self):
        print("Port         Status       LockOnReset")
        for uid in self.SED.ports.keys():
            # If default cred, use them, else look up via keymanager
            if self.SED.checkPIN("SID", bytes(self.SED.mSID, encoding='utf8')) == True:
                port = self.SED.getPort(uid, authAs=("SID", bytes(self.SED.mSID, encoding='utf8')))
            else:
                port = self.SED.getPort(uid, authAs=("SID", self.keyManager.getKey(self.wwn, "SID")))
            if port is not None and hasattr(port, 'Name'):
                print("{}{}{}{}{}".format(
                    port.Name,                                                # Port Name
                    (13 - len(port.Name)) * " ",                              # Whitespace padding
                    ("Unlocked","Locked")[port.PortLocked],                   # Port State
                    (13 - len(("Unlocked","Locked")[port.PortLocked])) * " ", # Whitespace padding
                    ("Disabled","Enabled")[port.LockOnReset],                 # Lock on Reset State
                    ))

    #********************************************************************************
    ##        name: configurePort
    #  description: configures the indicated port
    #   parameters:
    #               portname - The port to configure ("FWDownload" or "UDS")
    #             lock_state - If true, lock the band. If false, unlock the band
    #    lock_on_reset_state - If true, enable lock-on-reset. If false, disable lock-on-reset
    #********************************************************************************
    def configurePort(self, portname, lock_state=True, lock_on_reset_state=True):
        for uid in self.SED.ports.keys():
            port = self.SED.getPort(uid, authAs=("SID", self.keyManager.getKey(self.wwn, "SID")))
            if port is not None and hasattr(port, "Name") and port.Name == portname:
                if self.SED.setPort(
                    uid,
                    PortLocked=lock_state,
                    LockOnReset=lock_on_reset_state,
                    authAs=("SID", self.keyManager.getKey(self.wwn, "SID"))):
                        print("Sucessfully {} {}".format(("unlocked","locked")[lock_state], port.Name))
                        return True

    #********************************************************************************
    ##        name: lockPort
    #  description: Locks the indicated port
    #   parameters:
    #               portname - The port to lock/unlock ("FWDownload" or "UDS")
    #             lock_state - If true, lock the port. If false, unlock the port
    #********************************************************************************
    def lockPort(self, portname):
        return self.configurePort(portname, True)

    #********************************************************************************
    ##        name: unlockPort
    #  description: unocks the indicated port
    #   parameters:
    #               portname - The port to unlock ("FWDownload" or "UDS")
    #********************************************************************************
    def unlockPort(self, portname):
        return self.configurePort(portname, False)

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
    #********************************************************************************
    def enableFIPS(self):
        if self.SED.checkPIN("SID", bytes(self.SED.mSID, encoding='utf8')) == True:
            print("Take ownership of drive before enabling FIPS")
            return False

        # Check that all enabled bands are locked
        for bandNumber in range(0, 2):
            lockingInfo, status = self.SED.getRange(
                bandNumber, "EraseMaster", authAs=("EraseMaster", self.keyManager.getKey(self.wwn, "EraseMaster")))
            if lockingInfo.ReadLockEnabled and lockingInfo.WriteLockEnabled:
                print("Band{} Locking Enabled".format(bandNumber))
            else:
                print("Band{} Locking Disabled - enable before retrying enablefipsmode".format(bandNumber))
                return False

        # Disable Makers Authority
        if self.SED.enableAuthority(
            'SID', False, 'Makers', authAs=("SID", self.keyManager.getKey(self.wwn, "SID"))) == False:
            print("Failed to disable Makers Authority")
            return False

        # Disable Firmware Download
        if not self.lockPort("FWDownload"):
            return False

        if self.SED.fipsApprovedMode==True:
            print("FIPS mode of the drive enabled successfully")
            return True
        else:
            print("Failed to enable FIPS mode")
            return False

    #********************************************************************************
    ##        name: isOwned
    #********************************************************************************
    def isOwned(self, userList = ["SID", "EraseMaster", "BandMaster0", "BandMaster1"]):
        isOwned = False
        for user in userList:
            if self.SED.checkPIN(user, bytes(self.SED.mSID, encoding='utf8')) != True:
                isOwned = True

        return isOwned

    #********************************************************************************
    # Debug routine
    #********************************************************************************
    def bandTest(self, bandNumber):
        pass

#***********************************************************************************************************************
## Notes
#  Working - takeOwnership, rotateKeys, lockPort, configureBands(1), lockBand, eraseBand
#  Not Working - configureBands (2+), eraseDrive
#
#***********************************************************************************************************************
def main(arguments):
    opts = parse_args()
    SEDConfig = cSEDConfig(opts.device, opts.keymanager, opts)

    if opts.operation == 'configureband':
        SEDConfig.configureBands(opts.bandno, opts.rangestart, opts.rangelength, lock_state=False, lock_on_reset_state=opts.lockonreset)
        SEDConfig.printBandInfo(opts.bandno)
        pass

    elif opts.operation == 'configureport':
        SEDConfig.configurePort(opts.port, lock_state=False, lock_on_reset_state=opts.lockonreset)
        SEDConfig.printPortStatus()
        pass

    elif opts.operation == 'enablefipsmode':
        SEDConfig.enableFIPS()
        pass

    elif opts.operation == 'eraseband':
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
        SEDConfig.takeOwnership(['BandMaster{}'.format(opts.bandno)])
        pass

    elif opts.operation == 'giveupownership':
        SEDConfig.giveUpOwnership()
        pass

    elif opts.operation == 'lockband':
        SEDConfig.lockBand(opts.bandno)
        SEDConfig.printBandInfo(opts.bandno)
        pass

    elif opts.operation == 'lockport':
        SEDConfig.lockPort(opts.port)
        SEDConfig.printPortStatus()
        pass

    elif opts.operation == 'printbandinfo':
        SEDConfig.printBandInfo(opts.bandno)
        pass

    elif opts.operation == 'printdriveinfo':
        SEDConfig.printDriveInfo()
        print('')
        SEDConfig.printPortStatus()
        pass

    elif opts.operation == 'revertdrive':
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

    elif opts.operation == 'rotatekeys':
        SEDConfig.rotateKeys()
        pass

    elif opts.operation == 'takeownership':
        if SEDConfig.SED.SSC == "Enterprise":
            userList = ["SID", "EraseMaster", "BandMaster0", "BandMaster1"]
        else:
            userList = ["SID", "Admin1", "User1", "User2"]
        SEDConfig.takeOwnership(userList)
        pass

    elif opts.operation == 'unlockband':
        SEDConfig.unlockBand(opts.bandno)
        SEDConfig.printBandInfo(opts.bandno)
        pass

    elif opts.operation == 'unlockport':
        SEDConfig.unlockPort(opts.port)
        SEDConfig.printPortStatus()
        pass

    else:
        pass

# ****************************************************************************
if __name__ == '__main__':
    main(sys.argv)
    