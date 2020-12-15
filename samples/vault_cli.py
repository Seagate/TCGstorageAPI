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

# Add TCGstorageAPI path
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))

import keymanager_vault as keyManager
from TCGstorageAPI.tcgapi import Sed as SED

def parse_args():
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('-psid', default="VUTSRQPONMLKJIHGFEDCBA9876543210",
                        help='The PSID of the drive, used for factory restore, found on drive label')

    parser.add_argument('-json', default="cred.json",
                        help='The name of the json file which stores the credentials')

    opts = parser.parse_args()

    return opts

class cCredentials(object):
    def __init__(self, opts):
        # Init class variables
        self.opts = opts

        # Create the credential dictionary by reading in a json file
        if os.path.isfile(self.opts.json):
            with open(self.opts.json) as json_file:
                self.cred_table = json.load(json_file)

        # Create the credential dictionary from scratch if it doesn't exist
        else:
            self.cred_table = {
                'SID': '',
                'EraseMaster': '',
                'BandMaster0': '',
                'BandMaster1': '',
                'BandMaster2': '',
                'BandMaster3': '',
                'BandMaster4': '',
                'BandMaster5': '',
                'BandMaster6': '',
                'BandMaster7': '',
                'BandMaster8': '',
                'BandMaster9': '',
                'BandMaster10': '',
                'BandMaster11': '',
                'BandMaster12': '',
                'BandMaster13': '',
                'BandMaster14': '',
                'BandMaster15': '',
            }

            #self.cred_table['SID'] = generateRandomValue()
            #self.cred_table['EraseMaster'] = generateRandomValue()
            #self.cred_table['BandMaster0'] = generateRandomValue()
            #self.cred_table['BandMaster1'] = generateRandomValue()

            # Write the new values to file
            with open(self.opts.json, 'w+') as json_file:
                json_file.write(json.dumps(self.cred_table))

    def updateCredential(self, user, passwd):
        # Update the Dictionary
        if user in self.cred_table.keys():
            self.cred_table[user] = passwd
        else:
            print('User {} doesnt exist'.format(user))

        # Write the new value to file
        with open(self.opts.json, 'w+') as json_file:
            json_file.write(json.dumps(self.cred_table))


class cSEDConfig(object):

    def __init__(self, deviceHandle, opts):

        #Initialize Class Variables
        self.log_filename = os.path.join(os.path.dirname(__file__), 'sedcfg.log')
        self.deviceHandle = deviceHandle
        self.opts = opts

        # Initialize Logger
        logging.basicConfig(
            filename=self.log_filename,
            format="%(asctime)s %(name)s (%(threadName)s) - %(message)s",
            level=logging.DEBUG)
        self.logger = logging.getLogger(self.log_filename)

        # Initialize Vault
        server = 'http://10.1.156.120:8200/v1/'
        container = 'SeagateSecure'
        self.keyManager = keyManager.Vault(server, container)

        # Initialize the SED object
        self.SED = SED(self.deviceHandle, callbacks=self)
        
        # Get the WWN in STR format
        self.wwn = format(self.SED.wwn, 'X')

        # Initialze the cred_table
        self.myCreds = cCredentials(opts)
        
        # Initialize the mSID
        self.initial_cred = self.SED.mSID

        # Check Security Type
        if self.SED.SSC == "Enterprise":
            print("SED configuration is Enterprise")
        elif self.SED.SSC == "Opalv2":
            print("SED configuration is Opalv2")
        else:
            print("SED configuration is Unknown/Unsupported (Type {}) - Exiting Script".format(self.SED.SSC))
            sys.exit()

    def printDriveInfo(self):
        print("Drive Handle = {}".format(self.deviceHandle))
        print("WWN          = {:X}".format(self.SED.wwn))
        print("MSID         = {}".format(self.SED.mSID))
        print("MaxLBA       = 0x{:X}".format(self.SED.maxLba))
        print("Is Locked    = {}".format(self.SED.hasLockedRange))

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

    def takeOwnership(self):
        retVal = True
        userList = ["SID", "EraseMaster", "BandMaster0", "BandMaster1"]

        # Update each credential
        for user in userList:
            newValue = self.keyManager.generateRandomValue()
            if self.SED.checkPIN( user, bytes(self.SED.mSID, encoding='utf8')) == True:
                self.SED.changePIN(user, newValue, (None, self.initial_cred))
                if self.SED.checkPIN(user, newValue):
                    print("Took ownership of {}".format(user))
                    self.keyManager.setKey(self.wwn, user, newValue)
                else:
                    print("Failed to take ownership of {}".format(user))
                    retVal = False
            else:
                print("Ownership of {} already taken".format(user))
        return retVal

    def rotateKeys(self):
        retVal = True
        for user in self.myCreds.cred_table.keys():
            if self.myCreds.cred_table[user]:
                newValue = self.keyManager.generateRandomValue()
                self.SED.changePIN( user, newValue, (user, self.keyManager.getKey(self.wwn, user)))
                if self.SED.checkPIN( user, newValue ):
                    print("Successfully Updated {}".format(user))
                    self.keyManager.setKey(self.wwn, user, newValue)
                else:
                    print("Error Updating {}".format(user))
                    retVal = False
        return retVal

    def configureBands(self, bandNumber, rangeStart=None, rangeLength=None, lockOnReset=True):
        self.logger.debug("Configuring bands on the drive")
        if self.SED.checkPIN("SID", bytes(self.SED.mSID, encoding='utf8')) == True:
            print("Take ownership of drive before configuring")
            return False

        # Configure Band
        user = "BandMaster{}".format(bandNumber)
        configureStatus = self.SED.setRange(
            user,
            int(bandNumber),
            authAs=(user, self.keyManager.getKey(user)),
            RangeStart=int(rangeStart) if rangeStart is not None else None,
            RangeLength=int(rangeLength) if rangeStart is not None else None,
            ReadLockEnabled=1,
            WriteLockEnabled=1,
            LockOnReset=lockOnReset,
            ReadLocked=0,
            WriteLocked=0,
            )
        
        if configureStatus:
            print("Band{} is configured".format(bandNumber))
            return True
        else:
            print("Error configuring Band{}".format(bandNumber))
            return False

    def printBandInfo(self, bandNumber):
        user = "BandMaster{}".format(bandNumber)
        info, rc = self.SED.getRange(bandNumber, user, authAs=("EraseMaster", self.keyManager.getKey("EraseMaster")))
        print("Band{} RangeStart       = 0x{:x}".format(bandNumber, info.RangeStart))
        print("Band{} RangeEnd         = 0x{:x}".format(bandNumber, info.RangeStart + info.RangeLength))
        print("Band{} RangeLength      = 0x{:x}".format(bandNumber, info.RangeLength))
        print("Band{} ReadLocked       = {}".format(bandNumber, ("unlocked","locked")[info.ReadLocked]))
        print("Band{} WriteLocked      = {}".format(bandNumber, ("unlocked","locked")[info.WriteLocked]))
        print("Band{} LockOnReset      = {}".format(bandNumber, info.LockOnReset))
        print("Band{} WriteLockEnabled = {}".format(bandNumber, ("False","True")[info.WriteLockEnabled]))
        print("Band{} ReadLockEnabled  = {}".format(bandNumber, ("False","True")[info.ReadLockEnabled]))
        return rc

    def lockBand(self, bandNumber, lock_state=True):
        user = "BandMaster{}".format(bandNumber)
        configureStatus = self.SED.setRange(
            user,
            int(bandNumber),
            authAs=(user, self.keyManager.getKey(user)),
            LockOnReset=lock_state,
            ReadLocked=lock_state,
            WriteLocked=lock_state
            )
        if configureStatus:
            print("Band{} is {}".format(bandNumber, ("unlocked","locked")[lock_state]))
            return True
        else:
            print("Error {} Band{}".format(("unlocking","locking")[lock_state]), bandNumber)
            print(type(configureStatus))
            return False

    def unlockBand(self, bandNumber):
        return self.lockBand(bandNumber, False)

    def eraseBand(self, bandNumber):
        user = "BandMaster{}".format(bandNumber)
        if self.SED.erase(bandNumber, authAs=("EraseMaster", self.keyManager.getKey("EraseMaster"))):
            print("Band{} sucessfully erased".format(bandNumber))
            return True
        else:
            print("Error - Band{} was not erased".format(bandNumber))
            return False

    def eraseDrive(self):
        if self.SED.revert(self.opts.psid):
            print("Drive succesfully erased and reverted to factoring settings")
            return True
        else:
            print("Drive was not erased, check that the PSID is correct")
            print("Entered PSID - \"{}\"".format(self.opts.psid))
            return False

    def printPortStatus(self):
        print("Port         Locked       LockOnReset")
        for uid in self.SED.ports.keys():
            port = self.SED.getPort(uid, authAs=("SID", self.keyManager.getKey("SID")))
            if port is not None and hasattr(port, 'Name'):
                print("{}{}{}{}{}".format(
                    port.Name,                                                # Port Name
                    (13 - len(port.Name)) * " ",                              # Whitespace padding
                    ("Unlocked","Locked")[port.PortLocked],                   # Port State
                    (13 - len(("Unlocked","Locked")[port.PortLocked])) * " ", # Whitespace padding
                    ("Unlocked","Locked")[port.LockOnReset],                  # Lock on Reset State
                    ))

    def lockPort(self, portname, lock_state=True, lock_on_reset_state=True):
        '''
        Parameters:
          portname - Can be either "FWDownload" or "UDS"
        '''
        for uid in self.SED.ports.keys():
            port = self.SED.getPort(uid, authAs=("SID", self.keyManager.getKey("SID")))
            if port is not None and hasattr(port, "Name") and port.Name == portname:
                if self.SED.setPort(
                    uid,
                    PortLocked=lock_state,
                    LockOnReset=lock_on_reset_state,
                    authAs=("SID", self.keyManager.getKey("SID"))):
                        print("Sucessfully {} {}".format(("unlocked","locked")[lock_state], port.Name))

    def unlockPort(self, portname):
        return self.lockPort(portname, False, False)

    def bandTest(self, bandNumber):
        user = "BandMaster{}".format(bandNumber)
        configureStatus = self.SED.setRange(
            "EraseMaster",
            int(bandNumber),
            authAs=("EraseMaster", self.keyManager.getKey("EraseMaster")),
            )
        if configureStatus:
            print("Successful")
        else:
            print("Error")
            return False

# ****************************************************************************
# Notes
# Working - takeOwnership, rotateKeys, lockPort, configureBands(1), lockBand, eraseBand
# Not Working - configureBands (2+), eraseDrive
#
# ****************************************************************************
def main(arguments):
    opts = parse_args()
    SEDConfig = cSEDConfig('/dev/sdb', opts)
    SEDConfig.printDriveInfo()
    #SEDConfig.takeOwnership()
    SEDConfig.rotateKeys()
    #SEDConfig.eraseBand(1)
    #SEDConfig.configureBands(1, rangeStart=0x100000, rangeLength=0x100000)
    #SEDConfig.printBandInfo(1)
    #SEDConfig.lockBand(1)
    #SEDConfig.unlockBand(1)
    #SEDConfig.eraseBand(2)
    #SEDConfig.bandTest(2)
    #SEDConfig.configureBands(2, 0x20000, 0x10000)
    #SEDConfig.lockBand(0, True)
    #SEDConfig.printDriveInfo()
    #SEDConfig.lockBand(0, 0)
    #SEDConfig.eraseDrive()
    

# ****************************************************************************
if __name__ == '__main__':
    main(sys.argv)
    