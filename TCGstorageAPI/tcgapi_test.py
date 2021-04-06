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
# \file test_tcgapi.py
# \brief Implementation of unit tests for the TCG API methods
#
#-----------------------------------------------------------------------------

import unittest
from TCGstorageAPI.tcgapi import Sed, SedObject, PskCipherSuites
import unittest.mock as mock
import logging
from TCGstorageAPI.pysedSupport import *
from TCGstorageAPI.tcgSupport import *
import uuid
import platform
import random

class unitTests(unittest.TestCase):

    '''
    Class for testing the methods withing the Sed class in the tcgapi.py
    '''

    @mock.patch('TCGstorageAPI.tcgapi.pysed.Sed')
    def setUp(self, mock_class):

        # Creating the mock object
        self.sedmock = mock.MagicMock()
        mock_class.return_value = self.sedmock
        self.sedmock._cipherSuites.return_value = None
        
        # Creating the Sed object with mocked values
        if platform.system() == "Linux":
            self.sed = Sed("/dev/sd?", callbacks=self)
        if platform.system() == "Windows":
            self.sed = Sed("\\\\.\\PhysicalDrive?", callbacks=self)        

        # The mSID value for the drive
        self.sed_dev = self.sed.mSID

        # A mocked key object value used in gen_key
        self.sed.range_key = range_key = 0x000008060203001

        # An example payload to be signed using the drive's private key for the tperSign function
        self.sed.sample_string = 'hello_world'

        # Sample Locking Range Object Values
        self.sed.range_objs = ['ACE_Locking_Range1_Set_RdLocked', 'ACE_Locking_Range1_Set_WrLocked', 'ACE_Locking_Range2_Set_RdLocked']

        # Mock value for device wwn
        self.sed.mocked_wwn = "0x5000c590b9ae78e4"
        
        # Generating a random PSID value 
        self.sed.mocked_psid = ''.join(random.choice(string.ascii_uppercase + string.digits) for i in range(33)) 

        # A mocked value of the tableNo used to provide Datastore table write access to the host
        self.sed.tableNo = 1

        # A dictionary containing random port values mocked from the drive
        self.sed.ports_dict = {281483566710785: 1, 281483566710786: 0, 281483566710787: 1, 281483566710798: 1}

        # Authorities for Enterprise and Opal drives
        self.sed.auth_SID = "SID"
        self.sed.auth_Admin = "Admin1"
        self.sed.auth_BandMaster = "BandMaster1"
        self.sed.auth_Erasemaster = "EraseMaster"
        self.sed.auth_obj = "C_PIN_Admin1"

        # Valid credential 
        self.sed.valid_cred = '22'

        # Invalid credential
        self.sed.invalid_cred = '123'

        # A mocked value representing the uid of the second port of the drive
        self.sed.port_No_2 = 281483566710786

        # A mocked value representing the band number to modify/read from the drive
        self.sed.rangeNo = 1

        # A mocked value representing the ordinate of the entry to read (integer) into the TlsPsk table.
        self.sed.psk = 2

        # A mocked value representing the Ciphersuites in bytes
        self.sed.CipherSuite = b'\x00\xaa'

        # A mocked value of the bytearray of the tper_attestation certificate returned from the drive
        self.sed.cert = bytearray(b'0\x82\x05@0\x82\x03\xa8\xa0\x03\x02\x01\x02\x02\x15\x00\xb79\xbd\x01\x93')

        # UID returned from the drive in bytes
        self.sed.uid_bytes = b'0\x82\x04;0\x82\x03#\xa0\x03\x02\x01\x02\x02\x14F+\xe2m+...\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' 

        # UID returned from a FIPS drive in bytes
        self.sed.uid_opal = b'U\x93\xac\x98r\x00\x00\x00d\x88\x8c)}\xa3\x01\xeb\xd7|\xe2G\xa3q%\xeb_#k\x80\xb9~\xff\x02g\x9ff\x9c\x9e\xa68]\x80\x02}q\x00(X\x04\x00\x00\x00fipsq\x01NX\x02\x00\x00\x00ivq\x02c_codecs\nencode\nq\x03X\x16\x00\x00\x00}\x08 \xc3\xbc\xc3\xbd\x05H\x14\xc2\xbf\x1b\x15\xc2\x98\xc2\x97f}\xc3\x9bq\x04X\x06\x00\x00\x00latin1q\x05\x86q\x06Rq\x07X\x03\x00\x00\x00Idsq\x08]q\t(NNNNeu.\x00\x00' 
        
        # An example of data used to write to the SED Datastore
        self.sed.data = {  'fips':          {'descriptorVersion': 'RSE3  140-2 Module', 'securityLevel': 50} ,                # The FIPS status of the drive.
                           'iv':            uuid.uuid4().bytes,                                                               # initialization vector for self.sed for hashes/wrappings
                           'Ids':           [None, None, None, None],                                                         # random keyID's for each credential
        }
        

    def range_convert(self, kwrv):

        '''
        Helper function to handle conversion of data specific to getRange/setRange functions
        '''

        str_kwrv = convert(kwrv)
        
        if len(str_kwrv) == 0:
            return None, True
        if self.sed.SSC != 'Enterprise':
            for key in list(locking_table.keys()):
                str_kwrv[key] = str_kwrv[locking_table[key]]
            for key in list(str_kwrv.keys()):
                if not isinstance(key, str):
                    del str_kwrv[key]
        str_kwrv['LockOnReset'] = 0 in str_kwrv['LockOnReset']
        return str_kwrv

    def port_convert(self, kwrv):

        '''
        Helper function for handling the conversion of data specific to port functions
        '''

        str_kwrv = convert(kwrv)
        
        if self.sed.SSC != 'Enterprise':
            for key, val in portlocking_table.items():
                str_kwrv[key] = str_kwrv[portlocking_table[key]]

        if 'LockOnReset' in str_kwrv:
            str_kwrv['LockOnReset'] = 0 in str_kwrv['LockOnReset']
        if 'PortLocked' in kwrv:
            str_kwrv['PortLocked'] = bool(str_kwrv['PortLocked'])
        if 'UID' in str_kwrv:
            str_kwrv['UID'] = self.sed.port_No_2
        return str_kwrv   

    def psk_convert(self, kwrv):

        '''
        Helper function for handling the conversion of data specific to getpsk/setpsk functions
        '''

        str_kwrv = convert(kwrv)
        
        if self.sed.SSC == 'Opalv2':
            for key, val in c_tls_psk_table.items():
                str_kwrv[key] = str_kwrv[c_tls_psk_table[key]]

        if 'CipherSuite' in kwrv:
            str_kwrv['CipherSuite'] = PskCipherSuites.Name(int(str_kwrv['CipherSuite'],16))

        return str_kwrv

    def test_setRange_success(self):
            
        self.sedmock.invoke.return_value = status, rv, kwrv = (0, [1], {})

        # Enterprise Test case
        self.assertTrue(self.sed.setRange(self.sed.auth_BandMaster, self.sed.rangeNo, authAs=(self.sed.auth_BandMaster, self.sed_dev), RangeStart=8, RangeLength=64,
                                    ReadLockEnabled=1, WriteLockEnabled=1, LockOnReset=str(True),
                                    ReadLocked=0, WriteLocked=0))

        # OPAL test case
        self.assertTrue(self.sed.setRange(self.sed.auth_Admin, self.sed.rangeNo, authAs=(self.sed.auth_Admin, self.sed_dev), RangeStart=8, RangeLength=64,
                                    ReadLockEnabled=1, WriteLockEnabled=1, LockOnReset=str(True),
                                    ReadLocked=0, WriteLocked=0))

    def test_setRange_failure(self):
            
        self.sedmock.invoke.return_value = status, rv, kwrv = (1, [], {})

        # Enterprise Test case
        self.assertFalse(self.sed.setRange(self.sed.auth_BandMaster, self.sed.rangeNo, authAs=(self.sed.auth_BandMaster, self.sed_dev), RangeStart=8, RangeLength=64,
                                    ReadLockEnabled=1, WriteLockEnabled=1, LockOnReset=str(True),
                                    ReadLocked=0, WriteLocked=0))

        # OPAL test case
        self.assertFalse(self.sed.setRange(self.sed.auth_Admin, self.sed.rangeNo, authAs=(self.sed.auth_Admin, self.sed_dev), RangeStart=8, RangeLength=64,
                                    ReadLockEnabled=1, WriteLockEnabled=1, LockOnReset=str(True),
                                    ReadLocked=0, WriteLocked=0))


    def test_getRange_success_enterprise(self):

        type(self.sedmock).SSC = mock.PropertyMock(return_value='Enterprise')

        # kwrv contains the range object for Enterprise drives
        self.sedmock.invoke.return_value = status, rv, kwrv = (0, [], {'ReadLocked': 0, 
                                                            'UID': '\x00\x00\x08\x02\x00\x00\x00\x02', 
                                                            'CommonName': 'Locking', 
                                                            'RangeLength': 64, 
                                                            'ReadLockEnabled': 1, 
                                                            'ActiveKey': '\x00\x00\x08\x06\x00\x00\x00\x02', 
                                                            'WriteLockEnabled': 1, 
                                                            'WriteLocked': 0, 
                                                            'RangeStart': 8, 
                                                            'LockOnReset': [1], 
                                                            '_AllowATAUnlock': 0, 
                                                            'Name': 'Band1'})
                                                  
        r1, r2 = (self.sed.getRange(self.sed.rangeNo,self.sed.auth_SID,authAs=(self.sed.auth_BandMaster, self.sed_dev)))
        x = self.range_convert(kwrv)
        l1 = SedObject(x)
        l2 = True

        assert r1.Name == l1.Name
        assert r1.RangeStart == l1.RangeStart
        assert r1.RangeLength == l1.RangeLength
        assert r1.LockOnReset == l1.LockOnReset
        assert r1.ReadLockEnabled == l1.ReadLockEnabled
        assert r1.RangeStart == l1.RangeStart
        assert r1.WriteLockEnabled == l1.WriteLockEnabled
        assert r1.ReadLocked == l1.ReadLocked
        assert r1.WriteLocked == l1.WriteLocked
        assert r1.UID == l1.UID
        assert r1._AllowATAUnlock == l1._AllowATAUnlock
        assert r2 == l2

    def test_getRange_success_opal(self):

        # kwrv contains the range object for Opal drives
        self.sedmock.invoke.return_value = status, rv, kwrv = (0, [], {0: '\x00\x00\x08\x02\x00\x03\x00\x01', 
                                                                       1: 'Locking_Range1', 
                                                                       2: '', 
                                                                       3: 8, 
                                                                       4: 64, 
                                                                       5: 1, 
                                                                       6: 1, 
                                                                       7: 0, 
                                                                       8: 0, 
                                                                       9: [0], 
                                                                       10: '\x00\x00\x08\x06\x00\x03\x00\x01', 
                                                                       4294901760: 0})

        r1, r2 = (self.sed.getRange(self.sed.rangeNo,self.sed.auth_Admin,authAs=(self.sed.auth_Admin,self.sed_dev)))
        x = self.range_convert(kwrv)
        l1 = SedObject(x)
        l2 = True
        assert r1.Name == l1.Name
        assert r1.RangeStart == l1.RangeStart
        assert r1.RangeLength == l1.RangeLength
        assert r1.LockOnReset == l1.LockOnReset
        assert r1.ReadLockEnabled == l1.ReadLockEnabled
        assert r1.RangeStart == l1.RangeStart
        assert r1.WriteLockEnabled == l1.WriteLockEnabled
        assert r1.ReadLocked == l1.ReadLocked
        assert r1.WriteLocked == l1.WriteLocked
        assert r1.UID == l1.UID
        assert r2 == l2

    def test_getRange_emptykwrv(self):
        
        self.sedmock.invoke.return_value = status, rv, kwrv = (0x00, None, {})
        r1, r2 = (self.sed.getRange(self.sed.rangeNo,self.sed.auth_SID,authAs=(self.sed.auth_SID, self.sed_dev)))
        assert r1 == None
        assert r2 == True

    def test_getRange_fail(self):
                
        self.sedmock.invoke.return_value = status, rv, kwrv = (0x01, None, None)

        # Enterprise Test Case
        self.assertFalse(self.sed.getRange(self.sed.rangeNo,self.sed.auth_SID,authAs=(self.sed.auth_BandMaster,self.sed.invalid_cred)))
        # Opal Test Case
        self.assertFalse(self.sed.getRange(self.sed.rangeNo,self.sed.auth_SID,authAs=(self.sed.auth_Admin,self.sed.invalid_cred)))

    def test_enable_range_access_success(self):
                    
        self.sedmock.invoke.return_value = status, rv, kwrv = (0, [], {})
        for obj in self.sed.range_objs:
                for userNo in range(1,50):
                    self.assertTrue(self.sed.enable_range_access(obj, 'User'+str(userNo), self.sed.auth_Admin,authAs=(self.sed.auth_Admin,self.sed_dev)))

    def test_enable_range_access_fail(self):
                    
        self.sedmock.invoke.return_value = status, rv, kwrv = (12, [], {})
        for obj in self.sed.range_objs: 
                for userNo in range(99,150):
                    self.assertFalse(self.sed.enable_range_access(obj, 'User'+str(userNo), self.sed.auth_Admin,authAs=(self.sed.auth_Admin,self.sed_dev)))                    

    def test_erase_band_success(self):

        self.sedmock.invoke.return_value = status, rv, kwrv = (0, [], {})
        for bandNo in range(1,250):
            self.assertTrue(self.sed.erase(bandNo, authAs=(self.sed.auth_Erasemaster, self.sed_dev)))

    def test_erase_band_fail(self):
        
        # Status code is set to 13 which translates to NOT_AUTHORIZED
        self.sedmock.invoke.return_value = status, rv, kwrv = (13, None, None)

        # Opal Test Case
        self.assertFalse(self.sed.erase(self.sed.rangeNo, authAs=(self.sed.auth_Admin, self.sed_dev))) 

        # Enterprise Test Case
        self.assertFalse(self.sed.erase(self.sed.rangeNo, authAs=(self.sed.auth_Erasemaster, self.sed.invalid_cred)))       
    
    def test_changePIN_authority_success(self):
            
        self.sedmock.invoke.return_value = status, rv, kwrv = (0, [1], {})

        # Enterprise Test Case
        self.assertTrue(self.sed.changePIN(self.sed.auth_SID,self.sed.valid_cred,authAs=(self.sed.auth_SID,self.sed_dev)))

        # Opal Test Case
        self.assertTrue(self.sed.changePIN(self.sed.auth_Admin,self.sed.valid_cred, authAs=(self.sed.auth_Admin,self.sed.valid_cred), obj=self.sed.auth_obj))

    def test_changePIN_authority_fail(self):
            
        self.sedmock.invoke.return_value = status, rv, kwrv = (0x01, None, None)

        # Enterprise Test Case
        self.assertFalse(self.sed.changePIN(self.sed.auth_SID,self.sed.invalid_cred,authAs=(self.sed.auth_SID,self.sed.invalid_cred)))

        # Opal Test Case
        self.assertFalse(self.sed.changePIN(self.sed.auth_Admin,self.sed.invalid_cred, authAs=(self.sed.auth_Admin,self.sed.invalid_cred), obj=self.sed.auth_obj))

    def test_getPort_table_emptykwrv(self):

        self.sedmock.invoke.return_value = status, rv, kwrv = (0, [[]], {})
        for uid in self.sed.ports_dict.keys():
                assert (self.sed.getPort(uid,authAs=(self.sed.auth_SID, self.sed.invalid_cred))) == None

    def test_getPort_table_success_enterpise_without_LockOnReset(self):
            

        type(self.sedmock).SSC = mock.PropertyMock(return_value='Enterprise')
        # kwrv contains the port table for Enterprise drives
        self.sedmock.invoke.return_value = status, rv, kwrv = (0, [], {b'UID': b'\x00\x01\x00\x02\x00\x01\x00\x02', b'Name': b'FWDownload', b'LockOnReset': [], b'PortLocked': 0})
        p = (self.sed.getPort(self.sed.port_No_2, authAs=(self.sed.auth_SID,self.sed.valid_cred)))
        x = self.port_convert(kwrv)
        l = SedObject(x)
        assert p.LockOnReset == l.LockOnReset
        assert p.Name == l.Name
        assert p.PortLocked == l.PortLocked
        assert p.UID == l.UID

    def test_getPort_table_success_enterpise_with_LockOnReset(self):
            
        type(self.sedmock).SSC = mock.PropertyMock(return_value='Enterprise')
        # kwrv contains the port table for Enterprise drives
        self.sedmock.invoke.return_value = status, rv, kwrv = (0, [], {b'UID': b'\x00\x01\x00\x02\x00\x01\x00\x03', b'Name': b'UDS', b'LockOnReset': [0], b'PortLocked': 1})
        p = (self.sed.getPort(self.sed.port_No_2, authAs=(self.sed.auth_SID,self.sed.valid_cred)))
        x = self.port_convert(kwrv)
        l = SedObject(x)
        assert p.LockOnReset == l.LockOnReset
        assert p.Name == l.Name
        assert p.PortLocked == l.PortLocked
        assert p.UID == l.UID
    
    def test_getPort_table_success_opal(self):
            
        type(self.sedmock).SSC = mock.PropertyMock(return_value='Opalv2')
        # kwrv contains the port table for Opal drives
        self.sedmock.invoke.return_value = status, rv, kwrv = (0, [], {0: b'\x00\x01\x00\x02\x00\x01\x00\x02', 1: b'FWDownload', 2: [], 3: 0})
        p = (self.sed.getPort(self.sed.port_No_2, authAs=(self.sed.auth_SID,self.sed.valid_cred)))
        x = self.port_convert(kwrv)
        l = SedObject(x)
        assert p.Name == l.Name
        assert p.PortLocked == l.PortLocked
        assert p.UID == l.UID

    def test_getPort_table_fail(self):
    
        self.sedmock.invoke.return_value = status, rv, kwrv = (0x01, None, None)
        for uid in self.sed.ports_dict.keys():
                self.assertFalse(self.sed.getPort(uid,authAs=(self.sed.auth_SID,self.sed.invalid_cred))) 

    def test_setPort_state_success(self):
            
        self.sedmock.invoke.return_value = status, rv, kwrv = (0, [1], {})
        for uid in self.sed.ports_dict.keys():  
            self.assertTrue(self.sed.setPort(uid, authAs=(self.sed.auth_SID,self.sed.valid_cred), PortLocked=True, LockOnReset=True))

    def test_setPort_state_not_authorized(self):
            
        self.sedmock.invoke.return_value = status, rv, kwrv = (0x01, [1], {})
        for uid in self.sed.ports_dict.keys():  
            self.assertFalse(self.sed.setPort(uid, authAs=(self.sed.auth_SID,self.sed.invalid_cred), PortLocked=True, LockOnReset=True))

    def test_setPort_state_fail(self):
            
        self.sedmock.invoke.return_value = status, rv, kwrv = (0x12, [1], {})
        for uid in self.sed.ports_dict.keys():                   
            self.assertFalse(self.sed.setPort(uid, authAs=(self.sed.auth_SID,self.sed.invalid_cred)))
            
    def test_getAuthority_success_enabled_true(self):
        
        self.sedmock.invoke.return_value = status, rv, kwrv = (0, [], {'Enabled':1})
        self.assertTrue(self.sed.getAuthority(self.sed.auth_Admin, 'Admin2', authAs=(self.sed.auth_Admin,self.sed_dev)))
    
    def test_getAuthority_success_enabled_false(self):
            
        self.sedmock.invoke.return_value = status, rv, kwrv = (0, [], {'Enabled':2})
        self.assertFalse(self.sed.getAuthority(self.sed.auth_Admin, 'Admin2', authAs=(self.sed.auth_Admin,self.sed.invalid_cred)))

    def test_getAuthority_false(self):
            
        self.sedmock.invoke.return_value = status, rv, kwrv = (0x01, [], {'Enabled':1})
        self.assertFalse(self.sed.getAuthority(self.sed.auth_Admin, 'Admin2', authAs=(self.sed.auth_Admin,self.sed.invalid_cred)))
    
    def test_enableAuthority_success(self):
            
        self.sedmock.invoke.return_value = status, rv, kwrv = (0, [1], {})
        self.assertTrue(self.sed.enableAuthority(self.sed.auth_Erasemaster,True,self.sed.auth_BandMaster,authAs=(self.sed.auth_Erasemaster,self.sed_dev)))
        
    def test_enableAuthority_fail(self):
            
        self.sedmock.invoke.return_value = status, rv, kwrv = (1, [1], {})

        # Enterprise Test Case
        self.assertFalse(self.sed.enableAuthority(self.sed.auth_BandMaster,True,self.sed.auth_BandMaster,authAs=(self.sed.auth_BandMaster,self.sed.invalid_cred)))
        
        # Opal Test Case
        self.assertFalse(self.sed.enableAuthority(self.sed.auth_Admin,False,self.sed.auth_BandMaster,authAs=(self.sed.auth_Erasemaster,self.sed.invalid_cred)))
        
    def test_retrieve_LockingInfo_table_success(self):
        
        # kwrv contains the LockingInfo table for Enterprise drives
        self.sedmock.invoke.return_value = status, rv, kwrv = (0, [], {'MaxRanges': 31, 
                                                                    'UID': '\x00\x00\x08\x01\x00\x00\x00\x01', 
                                                                    'LowestAlignedLBA': 0, 
                                                                    'EncryptSupport': 1, 
                                                                    'RowNumber': 0, 
                                                                    'LogicalBlockSize': 512, 
                                                                    'AlignmentRequired': 1, 
                                                                    'Version': 10, 
                                                                    'AlignmentGranularity': 8, 
                                                                    'KeysAvailableCfg': 0, 
                                                                    'MaxReEncryptions': 0, 
                                                                    'Name': 'Seagate SED'})
        
        li = self.sed.lockingInfo()
        test_obj = SedObject(kwrv)
        assert li.LogicalBlockSize == test_obj.LogicalBlockSize
        assert li.MaxReEncryptions == test_obj.MaxReEncryptions
        assert li.EncryptSupport == test_obj.EncryptSupport
        assert li.AlignmentGranularity == test_obj.AlignmentGranularity
        assert li.AlignmentRequired == test_obj.AlignmentRequired
        assert li.KeysAvailableCfg == test_obj.KeysAvailableCfg
        assert li.MaxRanges == test_obj.MaxRanges
        assert li.Name == test_obj.Name
        assert li.RowNumber == test_obj.RowNumber
        assert li.Version == test_obj.Version
        assert li.UID == test_obj.UID

    def test_retrieve_LockingInfo_table_fail(self):
        
        self.sedmock.invoke.return_value = status, rv, kwrv = (1, [], {})
        self.assertFalse(self.sed.lockingInfo())

    def test_revert_psid_plaintext_success(self):

        self.sedmock.invoke.return_value = status, rv, kwrv = (0, [], {})
        self.assertTrue(self.sed.revert(self.sed.mocked_psid))

    def test_revert_psid_wwn_success(self):
            
        self.sedmock.invoke.return_value = status, rv, kwrv = (0, [], {})
        self.assertTrue(self.sed.revert(self.sed.mocked_wwn))
    
    def test_revert_psid_hex_wwn_success(self):
            
        wwn = int(self.sed.mocked_wwn, 0)
        self.sedmock.invoke.return_value = status, rv, kwrv = (0, [], {})
        self.assertTrue(self.sed.revert(hex(wwn)))

    def test_revert_fail(self):

        self.sedmock.invoke.return_value = status, rv, kwrv = (0x01, None, None)
        self.assertFalse(self.sed.revert(self.sed.mocked_psid))

    def test_revert_lockingSP_success(self):
    
        self.sedmock.invoke.return_value = status, rv, kwrv = (0, [], {})
        self.assertTrue(self.sed.revert_lockingSP(self.sed.valid_cred))

    def test_revert_lockingSP_fail(self):

        self.sedmock.invoke.return_value = status, rv, kwrv = (0x01, None, None)
        self.assertFalse(self.sed.revert_lockingSP(self.sed.invalid_cred))

    def test_activate_lockingSP_success(self):
        
        self.sedmock.invoke.return_value = status, rv, kwrv = (0, [], {})
        self.assertTrue(self.sed.activate(self.sed.auth_Admin,authAs=(self.sed.auth_Admin,self.sed.valid_cred)))

    def test_activate_lockingSP_fail(self):

        self.sedmock.invoke.return_value = status, rv, kwrv = (0x01, None, None)
        self.assertFalse(self.sed.activate(self.sed.auth_Admin,authAs=(self.sed.auth_Admin,self.sed.mSID)))
    
    def test_tperSign_payload_success(self):
    
        self.sedmock.invoke.return_value = status, rv, kwrv = (0, [self.sed.uid_bytes], {})
        tper = self.sed.tperSign(self.sed.sample_string)
        assert tper == rv[0]

    def test_tperSign_payload_fail(self):
        
        self.sedmock.invoke.return_value = status, rv, kwrv = (0x01, None, None)
        self.assertFalse(self.sed.tperSign(self.sed.sample_string))

    def test_gettperSign_cert_success(self):
        
        self.sedmock.invoke.return_value = status, rv, kwrv = (0, [self.sed.uid_bytes], {})
        tper_cert = self.sed.get_tperSign_cert()
        rv_bytes = bytearray(rv[0])
        for i, element in reversed(list(enumerate(rv_bytes))):
            if element == 0:
                del rv_bytes[i]
            else:
                break
        assert tper_cert == bytearray(rv_bytes)

    def test_tperSign_cert_fail(self):
        
        self.sedmock.invoke.return_value = status, rv, kwrv = (0x01, None, None)
        self.assertFalse(self.sed.get_tperSign_cert())
    
    def test_tper_attestation_cert_success(self):

        self.sedmock.invoke.return_value = status, rv, kwrv = (0, [self.sed.cert], {})
        if self.sed.SSC == 'Enterprise':
            type(self.sedmock).SSC = mock.PropertyMock(return_value='Enterprise')
        else:
            type(self.sedmock).SSC = mock.PropertyMock(return_value='Opalv2')
        tper_attestation_cert = self.sed.get_tperAttestation_Cert()
        rv_bytes = bytearray(rv[0])
        for i, element in reversed(list(enumerate(rv_bytes))):
            if element == 0:
                del rv_bytes[i]
            else:
                break
        assert tper_attestation_cert == bytearray(rv_bytes)

    def test_per_attestation_cert_fail(self):
        
        self.sedmock.invoke.return_value = status, rv, kwrv = (0x01, None, None)
        self.assertFalse(self.sed.get_tperAttestation_Cert())
    
    def test_firmware_attestation_optional_param_success(self):

        assessor_nonce = '23helloseagate'
        sub_name = 'Seagate'
        assessor_ID = '42545254'

        if self.sed.SSC == 'Enterprise':
            type(self.sedmock).SSC = mock.PropertyMock(return_value='Enterprise')
        else:
            type(self.sedmock).SSC = mock.PropertyMock(return_value='Opalv2')
        self.sedmock.invoke.return_value = status, rv, kwrv = (0, [self.sed.uid_bytes], {})
        firmware_attestation_message = self.sed.firmware_attestation(assessor_nonce,sub_name,assessor_ID)
        assert firmware_attestation_message == rv

    def test_firmware_attestation_no_param_success(self):

        assessor_nonce = '23helloseagate'
        sub_name = None
        assessor_ID = None
        self.sedmock.invoke.return_value = status, rv, kwrv = (0, [self.sed.uid_bytes], {})
        firmware_attestation_message = self.sed.firmware_attestation(assessor_nonce,sub_name,assessor_ID)
        assert firmware_attestation_message == rv

    def test_firmware_attestation_fail(self):
        
        assessor_nonce = 'false_val'
        sub_name = 'false_val'
        assessor_ID = '425452'
        self.sedmock.invoke.return_value = status, rv, kwrv = (0x01, None, None)
        self.assertFalse(self.sed.firmware_attestation(assessor_nonce,sub_name,assessor_ID))

    def test_write_access_datastore_table_success(self):
                
        self.sedmock.invoke.return_value = status, rv, kwrv = (0, [], {})
        self.assertTrue(self.sed.writeaccess("User2", self.sed.tableNo, authAs=(self.sed.auth_Admin, self.sed_dev)))

    def test_write_access_datastore_table_User23(self):
        
        # Failure test case when passed in with higher User## values   
        self.sedmock.invoke.return_value = status, rv, kwrv = (1, [], {})
        self.assertFalse(self.sed.writeaccess("User23", self.sed.tableNo, authAs=(self.sed.auth_Admin, self.sed.invalid_cred)))

    def test_write_access_datastore_table_fail(self):
       
        self.sedmock.invoke.return_value = status, rv, kwrv = (0x01, None, None)
        self.assertFalse(self.sed.writeaccess("User1", self.sed.tableNo, authAs=(self.sed.auth_Admin, self.sed.invalid_cred)))

    def test_read_access_datastore_table_success(self):
                
        self.sedmock.invoke.return_value = status, rv, kwrv = (0, [], {})
        self.assertTrue(self.sed.readaccess("User1", self.sed.tableNo, authAs=(self.sed.auth_Admin, self.sed_dev)))

    def test_read_access_datastore_table_User32(self):
        
        # Failure test case when passed in with higher User## values
        self.sedmock.invoke.return_value = status, rv, kwrv = (0x01, None, None)
        self.assertFalse(self.sed.readaccess("User32", self.sed.tableNo, authAs=(self.sed.auth_Admin, self.sed.invalid_cred))) 

    def test_read_access_datastore_table_fail(self):
                
        self.sedmock.invoke.return_value = status, rv, kwrv = (1, [], {})
        self.assertFalse(self.sed.readaccess("User23", self.sed.tableNo, authAs=(self.sed.auth_Admin, self.sed.invalid_cred)))

    def test_readdata_SED_datastore_success_enterprise(self):

        self.sedmock.invoke.return_value = status, rv, kwrv = (0, [self.sed.uid_opal], {})
        read = self.sed.readData(self.sed.auth_SID,authAs=(self.sed.auth_SID,self.sed.valid_cred))
        l = fromSerialized(rv[0])
        assert read == l

    def test_read_data_SED_datastore_success_opal(self):

        self.sed.data_length = 97
        self.sedmock.invoke.return_value = status, rv, kwrv = (0, [self.sed.uid_opal], {})
        self.assertTrue(self.sed.readData('User1',authAs=('User1',self.sed.valid_cred)))

    def test_read_data_SED_datastore_success_emptyrv(self):
    
        self.sedmock.invoke.return_value = status, rv, kwrv = (0, [], {})
        read = self.sed.readData(self.sed.auth_SID,authAs=(self.sed.auth_SID,self.sed.invalid_cred))
        assert read == None

    def test_read_data_SED_datastore_checkPIN_true(self):
        
        self.sedmock._checkPIN.return_value = True
        self.sedmock.invoke.return_value = status, rv, kwrv = (0, [self.sed.uid_opal], {})        
        self.assertTrue(self.sed.readData(self.sed.auth_SID,authAs=(self.sed.auth_SID,self.sed_dev)))

    def test_read_data_SED_datastore_fail(self):
        
        self.sedmock.invoke.return_value = status, rv, kwrv = (0x01, None, None)
        self.assertFalse(self.sed.readData(self.sed.auth_SID,authAs=(self.sed.auth_SID,self.sed.invalid_cred)))

    def test_write_data_SED_datastore_success_enterprise(self):
        
        self.sedmock.invoke.return_value = status, rv, kwrv = (0, [1], {})
        self.assertTrue(self.sed.writeData(self.sed.auth_BandMaster,self.sed.data, authAs=(self.sed.auth_BandMaster,self.sed.valid_cred)))

    def test_write_data_SED_datastore_success_opal(self):
    
        self.sedmock.invoke.return_value = status, rv, kwrv =  (0, [self.sed.uid_bytes], {})
        self.assertTrue(self.sed.writeData('User1',self.sed.data, authAs=('User1',self.sed.valid_cred)))

    def test_write_data_SED_datastore_checkPIN_true(self):
        
        self.sedmock._checkPIN.return_value = True
        self.sedmock.invoke.return_value = status, rv, kwrv = (0, [1], {})
        self.assertTrue(self.sed.writeData(self.sed.auth_BandMaster,self.sed.data, authAs=(self.sed.auth_BandMaster, self.sed_dev)))

    def test_write_data_SED_datastore_fail(self):
            
        self.sedmock.invoke.return_value = status, rv, kwrv = (0x01, None, None)
        self.assertFalse(self.sed.writeData(self.sed.auth_BandMaster,self.sed.data, authAs=(self.sed.auth_BandMaster,self.sed.invalid_cred)))

    def test_get_media_encryption_key_success(self):
        
        # kwrv contains the UID in bytes from the drive
        self.sedmock.invoke.return_value = status, rv, kwrv = (0, [], {10: b'\x00\x00\x08\x06\x00\x03\x00\x01'}) 
        m1, m2 = self.sed.get_MEK(self.sed.rangeNo, self.sed.auth_Admin, authAs=(self.sed.auth_Admin,self.sed_dev))
        l1 = SedObject(kwrv)
        l2 = True
        print(l1)
        
    def test_get_media_encryption_key_fail(self):

        self.sedmock.invoke.return_value = status, rv, kwrv = (0x01, None, None)
        self.assertFalse(self.sed.get_MEK(self.sed.rangeNo, self.sed.auth_Admin, authAs=(self.sed.auth_Admin,self.sed.invalid_cred)))

    def test_genkey_secure_erase_range_success(self):
        
        self.sedmock.invoke.return_value = status, rv, kwrv = (0, [], {})
        self.assertTrue(self.sed.gen_key(self.sed.range_key, self.sed.auth_Admin, authAs=(self.sed.auth_Admin, self.sed_dev)))

    def test_genkey_secure_erase_range_fail(self):
            
        self.sedmock.invoke.return_value = status, rv, kwrv = (0x01, None, {})
        self.assertFalse(self.sed.gen_key(self.sed.range_key, self.sed.auth_Admin, authAs=(self.sed.auth_Admin, self.sed_dev)))

    def test_getPskEntry_success_enterprise(self):

        # kwrv contains the TlsPsk object with values read reflected from the TCG specification
        self.sedmock.invoke.return_value = status, rv, kwrv = (0, [], {b'CipherSuite': 'DHE_PSK_WITH_AES_128_GCM_SHA256', b'CommonName': b'', b'Enabled': 1, b'Name': b'TLS_PSK_Key0', b'UID': b'\x00\x00\x00\x1e\x00\x00\x00\x01'})
        p = self.sed.getPskEntry(self.sed.psk)
        kwrv = self.psk_convert(kwrv)
        mocked_return = SedObject(kwrv)
        assert p.Enabled == mocked_return.Enabled
        assert p.CommonName == mocked_return.CommonName
        assert p.Name == mocked_return.Name
        assert p.UID == mocked_return.UID
        assert p.CipherSuite == mocked_return.CipherSuite

    def test_getPskEntry_success_opal(self):

        type(self.sedmock).SSC = mock.PropertyMock(return_value='Opalv2')
        # kwrv contains the TlsPsk object with values read reflected from the TCG specification
        self.sedmock.invoke.return_value = status, rv, kwrv = (0, [], {0: '\x00\x00\x00\x1e\x00\x00\x00\x01', 1: 'TLS_PSK_Key1', 2: '', 3: 0, 5: '0xaa'})
        p = self.sed.getPskEntry(self.sed.psk)
        kwrv = self.psk_convert(kwrv)
        mocked_return = SedObject(kwrv)
        assert p.Enabled == mocked_return.Enabled
        assert p.CommonName == mocked_return.CommonName
        assert p.Name == mocked_return.Name
        assert p.UID == mocked_return.UID

    def test_getPskEntry_psk_Sedobject(self):

        psk = {'Name':'sample'}
        l1 = SedObject(psk)
        # kwrv contains the TlsPsk object with values read reflected from the TCG specification
        self.sedmock.invoke.return_value = status, rv, kwrv = (0, [], {'CipherSuite': '0xaa', 'CommonName': '', 'Enabled': 0, 'Name': 'TLS_PSK_Key0', 'UID': '0000001e00000001'})
        p = self.sed.getPskEntry(l1)
        kwrv = self.psk_convert(kwrv)
        mocked_return = SedObject(kwrv)
        assert p.Enabled == mocked_return.Enabled
        assert p.CommonName == mocked_return.CommonName
        assert p.Name == mocked_return.Name
        assert p.UID == mocked_return.UID
        assert p.CipherSuite == mocked_return.CipherSuite

    def test_getPskEntry_emptykwrv(self):
            
        self.sedmock.invoke.return_value = status, rv, kwrv = (0, [], {})
        assert (self.sed.getPskEntry(self.sed.psk)) == None

    def test_getPskEntry_fail(self):

        self.sedmock.invoke.return_value = status, rv, kwrv = (0x01, None, {})
        self.assertFalse(self.sed.getPskEntry(self.sed.psk)) 

    def test_setPskEntry_success_with_authAs(self):
            
        authAs = [(self.sed.auth_SID, self.sed_dev), (self.sed.auth_Erasemaster, self.sed_dev)]
        self.sedmock.invoke.return_value = status, rv, kwrv = (0, [], {})
        self.assertTrue(self.sed.setPskEntry(self.sed.psk, authAs=authAs, Enabled=True, CipherSuite=self.sed.CipherSuite, PSK=self.sed.uid_bytes))

    def test_setPskEntry_opal(self):
            
        type(self.sedmock).SSC = mock.PropertyMock(return_value='Opalv2')
        authAs = [(self.sed.auth_SID, self.sed_dev), (self.sed.auth_Admin, self.sed_dev)]
        self.sedmock.invoke.return_value = status, rv, kwrv = (0, [], {})
        self.assertTrue(self.sed.setPskEntry(self.sed.psk, authAs=authAs, Enabled=True,  CipherSuite=self.sed.CipherSuite, PSK=self.sed.uid_bytes))

    def test_setPskEntry_success_checkPIN_true(self):
            
        self.sedmock._checkPIN.return_value = True
        authAs = [(self.sed.auth_SID, self.sed_dev), (self.sed.auth_Erasemaster, self.sed_dev)]
        self.sedmock.invoke.return_value = status, rv, kwrv = (0, [], {})
        self.assertTrue(self.sed.setPskEntry(self.sed.psk, authAs=authAs, Enabled=True,  CipherSuite=self.sed.CipherSuite, PSK=self.sed.uid_bytes))

    def test_setPskEntry_success_psk_SedObject(self):
            
        sample_psk_object = {'Name':'sample'}
        authAs = [(self.sed.auth_SID, self.sed_dev), (self.sed.auth_Erasemaster, self.sed_dev)]
        self.sedmock.invoke.return_value = status, rv, kwrv = (0, [], {})
        l1 = SedObject(sample_psk_object)
        self.assertTrue(self.sed.setPskEntry(l1, authAs=authAs, Enabled=True, CipherSuite=self.sed.CipherSuite, PSK=self.sed.uid_bytes))

    def test_setPskEntry_fail(self):
            
        authAs = [(self.sed.auth_SID, self.sed.invalid_cred), (self.sed.auth_Erasemaster, self.sed.invalid_cred)]
        self.sedmock.invoke.return_value = status, rv, kwrv = (0x01, [], None)
        self.assertFalse(self.sed.setPskEntry(self.sed.psk, authAs=authAs, Enabled=True,  CipherSuite=self.sed.CipherSuite, PSK=self.sed.uid_bytes))

    def test_getAuthas_parameter_None(self):

        authAs = None
        return_tuple = (None, None)
        self.assertEquals(self.sed._getAuthAs(authAs), return_tuple)

    def test_getAuthas_parameter_tuple(self):

        authAs = (self.sed.auth_SID, self.sed.valid_cred)
        return_tuple = (self.sed.auth_SID, self.sed.valid_cred)
        self.assertEquals(self.sed._getAuthAs(authAs), return_tuple)

    def test_getAuthas_parameter_Anybody(self):

        authAs = ('Anybody', self.sed.valid_cred)
        self.assertEquals(self.sed._getAuthAs(authAs), 'Anybody')

    def test_getAuthas_parameter_defAuth(self):

        authAs = (self.sed.auth_SID, None)
        return_tuple = (self.sed.auth_SID, None)
        self.assertEquals(self.sed._getAuthAs(authAs), return_tuple)

    def test_ports_level0_information(self):

        self.sedmock.ports.return_value = self.sed.ports_dict
        self.assertEquals(self.sed.ports(), self.sed.ports_dict)
    
    def test_read_fips_compliance_descriptor(self):

        fips_return = {'standard': 'FIPS 140-2', 'securityLevel': 50, 'hardwareVersion': '1RD17D' }
        self.sedmock.fipsCompliance.return_value = fips_return
        self.assertEquals(self.sed.fipsCompliance(), fips_return)

    def test_read_fips_compliance_descriptor_none(self):

        fips_return = None
        self.sedmock.fipsCompliance.return_value = fips_return
        self.assertEquals(self.sed.fipsCompliance(), fips_return)

    def test_retrieve_wwn(self):

        self.sedmock.wwn.return_value = wwn = self.sedmock.mocked_wwn
        self.assertEquals(self.sed.wwn(), wwn)

    def test_retrieve_mSID(self):

        self.sedmock.mSID.return_value = mSID = self.sedmock.sed_dev
        self.assertEquals(self.sed.mSID(), mSID)

    def test_SSC_Enterprise(self):

        self.sedmock.SSC.return_value = SSC = 'Enterprise'
        self.assertEquals(self.sed.SSC(), SSC)

    def test_SSC_Opal(self):

        self.sedmock.SSC.return_value = SSC = 'Opalv2'
        self.assertEquals(self.sed.SSC(), SSC)

    def test_hasLockedRange_bands_true(self):

        self.sedmock.hasLockedRange.return_value = hasLockedRange = True
        self.assertTrue(self.sed.hasLockedRange())

    def test_hasLockedRange_bands_false(self):

        self.sedmock.hasLockedRange.return_value = hasLockedRange = False
        self.assertFalse(self.sed.hasLockedRange())

    def test_setMinPINLength_success(self):

        self.sedmock.invoke.return_value = status, rv, kwrv = (0, [], {})
        self.assertTrue(self.sed.setMinPINLength(self.sed.auth_Admin, 4, authAs=(self.sed.auth_SID,self.sed_dev)))

    def test_setMinPINLength_fail(self):

        self.sedmock.invoke.return_value = status, rv, kwrv = (0x01, None, None)
        self.assertFalse(self.sed.setMinPINLength(self.sed.auth_Admin, 4, authAs=(self.sed.auth_SID,self.sed.invalid_cred)))

    def test_fipsApprovedMode_flag_true(self):

        self.sedmock.fipsApprovedMode.return_value = fipsApprovedMode = True
        self.assertTrue(self.sed.fipsApprovedMode())

    def test_fipsApprovedMode_flag_false(self):

        self.sedmock.fipsApprovedMode.return_value = fipsApprovedMode = False
        self.assertFalse(self.sed.fipsApprovedMode())

    def test_current_CipherSuite_for_tls(self):

        self.sedmock.currentCipherSuite.return_value = self.sedmock.Ciphersuite
        self.assertEquals(self.sed.currentCipherSuite(), self.sedmock.Ciphersuite)
    
    def test_retrieve_max_addressable_Lba(self):

        self.sedmock.maxLba.return_value = maxLba = 5
        self.assertEquals(self.sed.maxLba(), maxLba)

if __name__ == "__main__":
    unittest.main(buffer=True)