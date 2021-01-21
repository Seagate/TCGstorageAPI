import argparse
import json
import logging
import os
import sys
import time

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

    parser.add_argument('--keymanager', default='vault', choices=('json', 'vault'),
                        help='The keymanager to use')

    parser.add_argument('--lockonreset', action='store_true', default=False,
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

    parser.add_argument('--operation', default='printdriveinfo', choices=(
        'addband',
        'bandtest',
        'configureband',
        'configureport',
        'enablefipsmode',
        'giveupownership',
        'eraseband',
        'lockband',
        'lockport',
        'printbandinfo',
        'printdriveinfo',
        'removeband',
        'revertdrive',
        'rotatekeys',
        'takeownership',
        'unlockband',
        'unlockport',
    ))

    opts = parser.parse_args()

    if opts.operation == 'revertdrive' and not opts.psid:
        parser.error('--psid argument is mandatory for the revertdrive operation')

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
        self.bandList = list()

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
            self.bandList.append('BandMaster0')
            self.bandList.append('BandMaster1')

        elif self.SED.SSC == 'Opalv2':
            self.logger.info('SED configuration is Opalv2')
            self.LockingSP = 'Admin1'
            self.LockingSP_Obj = 'C_PIN_Admin1'
            self.bandList.append('User1')

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
            print('FIPS Compliant = {}'.format(self.SED.fipsApprovedMode))
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
        for bandOwner in self.bandList:
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
            verb1 = "Gave Up"
            verb2 = "Give Up"
        else:
            verb1 = "Updated"
            verb2 = "Update"

        # Rotate Band Keys
        for bandOwner in self.bandList:
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
            return True
        else:
            print('Drive was not erased, check that the PSID is correct')
            print('Entered PSID - \'{}\''.format(self.opts.psid))
            return False


    #********************************************************************************
    def addBand(self, bandNumber):
        failureStatus = False
        if self.SED.SSC == 'Enterprise':
            print('Band Addition is not yet supported on Enerprise Configs')
            failureStatus = True
            return failureStatus

        elif self.SED.SSC == 'Opalv2':
            bandOwner = 'Band{}'.format(bandNumber)
            self.bandList.append(bandOwner)
            
            # Enable Band
            if self.SED.enableAuthority(self.LockingSP, True, bandOwner, authAs=(self.LockingSP, self.keyManager.getKey(self.wwn, self.LockingSP))):
                print('Enabled {}'.format(bandOwner))
            else:
                print('Failed to enable {}'.format(bandOwner))
                failureStatus = True

            # Setup Args
            auth = self.LockingSP
            authAs = (None, self.keyManager.getKey(self.wwn, self.LockingSP))
            obj = 'C_PIN_{}'.format(bandOwner)

            # Take ownership
            newKey = self.keyManager.generateRandomValue()
            self.SED.changePIN(auth, newKey, authAs, obj)
            if self.SED.checkPIN(bandOwner, newKey):
                print('Took ownership of {}'.format(bandOwner))
                self.keyManager.setKey(self.wwn, bandOwner, newKey)
            else:
                print('Failed to take ownership of {}'.format(bandOwner))
                failureStatus = True

        return failureStatus

    #********************************************************************************
    def removeBand(self, bandNumber):
        failureStatus = False
        if self.SED.SSC == 'Enterprise':
            print('Band Removal is not yet supported on Enerprise Configs')
            failureStatus = True
            return failureStatus

        elif self.SED.SSC == 'Opalv2':
            bandOwner = 'Band{}'.format(bandNumber)
            if bandOwner not in self.bandList:
                print('{} is not currently enabled'.format(bandOwner))
                failureStatus = True
                return failureStatus
            else:
                self.bandList.remove(bandOwner)

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
                        print('Sucessfully {} {}'.format(('unlocked','locked')[lock_state], port.Name))
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
    ##        name: isOwned
    #********************************************************************************
    def isOwned(self):
        return self.SED.checkPIN(self.AdminSP, self.initial_cred) != True

    #********************************************************************************
    def bandTest(self):
        

        for bandOwner in self.bandList:
            print(bandOwner)
            newKey = self.keyManager.generateRandomValue()
            if self.SED.SSC == 'Enterprise':
                auth = bandOwner
                authAs = (None, self.initial_cred)
                obj = None
            elif self.SED.SSC == 'Opalv2':
                auth = self.LockingSP
                authAs = (None, self.keyManager.getKey(self.wwn, self.LockingSP))
                obj = 'C_PIN_{}'.format(bandOwner)
            else:
                return True
            
            if self.SED.changePIN(auth, newKey, authAs, obj):
                self.keyManager.setKey(self.wwn, bandOwner, newKey)
                print('pass')

            if self.SED.checkPIN(bandOwner, newKey):
                print('Took ownership of {}'.format(bandOwner))
                self.keyManager.setKey(self.wwn, bandOwner, newKey)
            else:
                print('Failed to take ownership of {}'.format(bandOwner))

        pass

#***********************************************************************************************************************
def main(arguments):
    opts = parse_args()

    # Create the SEDConfig class
    SEDConfig = cSEDConfig(opts.device, opts.keymanager, opts)

    # "Switch" statement on operation
    if opts.operation == 'addband':
        #SEDConfig.addBand(opts.bandno)
        pass

    if opts.operation == 'bandtest':
        SEDConfig.bandTest()
        pass

    if opts.operation == 'configureport':
            SEDConfig.configurePort(opts.port, lock_state=False, lock_on_reset_state=opts.lockonreset)
            SEDConfig.printPortStatus()
            pass

    if opts.operation == 'giveupownership':
        SEDConfig.giveUpOwnership()
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
        
        SEDConfig.printSecurityInfo()
        pass

    if opts.operation == 'removeband':
        #SEDConfig.removeBand(opts.bandno)
        pass

    if opts.operation == 'revertdrive':
        timeToWait = 0 #JRM FIX back to 15
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

    if opts.operation == 'unlockport':
        SEDConfig.unlockPort(opts.port)
        SEDConfig.printPortStatus()
        pass

# ****************************************************************************
if __name__ == '__main__':
    main(sys.argv)