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
# \file tcgapi.py
# \brief Implementation of TCG API methods
#
#-----------------------------------------------------------------------------

import sys
import logging
from . import pysed
import struct
from . import pysedSupport
import warnings
from .pysedSupport import *
from . import tcgSupport
from .tcgSupport import locking_table as locking_table
from .tcgSupport import portlocking_table as portlocking_table
from .tcgSupport import c_tls_psk_table as c_tls_psk_table
import io

StatusCode = pysed.StatusCode


class PskCipherSuites(object):
    '''
    This is a class dealing with PskCipherSuites.
    Used optionally to provide support for TLS Secure Messaging.
    '''
    DHE_PSK_WITH_AES_128_GCM_SHA256 = 0x00AA
    PSK_WITH_AES_128_GCM_SHA256 = 0x00A8
    PSK_WITH_AES_256_GCM_SHA384 = 0x00A9
    DHE_PSK_WITH_AES_256_GCM_SHA384 = 0x00AB
    PSK_WITH_AES_128_CBC_SHA256 = 0x00AE
    PSK_WITH_AES_256_CBC_SHA384 = 0x00AF
    PSK_WITH_NULL_SHA256 = 0x00B0
    PSK_WITH_NULL_SHA384 = 0x00B1
    DHE_PSK_WITH_AES_128_CBC_SHA256 = 0x00B2
    DHE_PSK_WITH_AES_256_CBC_SHA384 = 0x00B3
    DHE_PSK_WITH_NULL_SHA256 = 0x00B4
    DHE_PSK_WITH_NULL_SHA384 = 0x00B5
    PSK_WITH_AES_128_CCM = 0x0CA4
    PSK_WITH_AES_256_CCM = 0x0CA5
    DHE_PSK_WITH_AES_128_CCM = 0x0CA6
    DHE_PSK_WITH_AES_256_CCM = 0x0CA7
    ECDHE_PSK_WITH_AES_128_CBC_SHA256 = 0x0C37
    ECDHE_PSK_WITH_AES_256_CBC_SHA384 = 0x0C38
    ECDHE_PSK_WITH_NULL_SHA256 = 0x0C3A
    ECDHE_PSK_WITH_NULL_SHA384 = 0x0C3B
    byValue = {'\xff\xff':None}

    @classmethod
    def _init(cls):
        for k, v in vars(cls).items():
            if isinstance(v, int):
                cls.byValue[v] = k
                cls.byValue[struct.pack('>H', v)] = k

    @classmethod
    def Name(cls, value):
        try:
            return cls.byValue[value]
        except KeyError:
            if value in vars(cls):
                return value
            if len(cls.byValue) == 1:
                cls._init()
                try:
                    return cls.byValue[value]
                except KeyError:
                    pass
            raise ValueError('Invalid CipherSuite value - ' + str(value))

    @classmethod
    def Value(cls, name):
        try:
            return getattr(cls, cls.Name(name))
        except KeyError:
            raise ValueError('Invalid CipherSuite name - ' + str(name))

    @classmethod
    def StringValue(cls, name):
        try:
            return struct.pack('>H', cls.Value(name))
        except KeyError:
            raise ValueError('Invalid CipherSuite name - ' + str(name))
        except ValueError:
            if name is None:
                return '\xff\xff'
            raise


class SedCallbacksStub(object):
    '''
    classdocs
    Hooks to provide mechanism that caches and gathers credentials to use in Sed methods.

    Overridable Attributes:
      logger    - (class or instance) A Python logger instance to use for logging.
                  If not supplied, will use the logger sed.xxxxx where xxxxx is the last
                  five digits of the drive wwn or base device name.

    '''

    def __init__(self, **kwargs):
        self.dataStore = None

    def getAuth(self, op, defAuth):
        '''
        Override the default authority used in an Sed call.  Example usage would be to
        provide any cached BandMaster credentials to a WriteData call.
        op      - The operation to be performed
        defAuth- The default authority (number) to be used for this request.

        Returns the name or authority id to use for this request.  If None, defAuth will be used.
        '''
        return defAuth

    def getCred(self, auth):
        '''
        Override the credentials used in an SED call.
        auth   - The authority as a number to be used for this request.

        Returns a Key object or a string containing the plain text credentials to be used.
        if None, the mSID will be used.
        '''
        return None

    def setCred(self, auth, key):
        '''
        Notification of a successful ChangePIN request.
        auth    - The authority id as a number that has been modified.
        key     - The new Key now in effect.
        '''
        return

    def failedCred(self, auth, cred):
        '''
        Notification of an unsuccessful request due to authentication failure.
        auth    - The Authority attempted as an integer.
        cred    - The Key/plainText credentials used.

        May return a new credential to use on retry.
        Returns None to stop authentication attempts.
        '''
        return None

    def fail(self, msg=None, op=None, status=None):
        '''
        Sets return code or raises an exception for failed operations.
        '''
        return False

    def configureTls(self, sed, cipherSuites):
        '''
        Used optionally to provide support for TLS Secure Messaging.
        Callback to solicit information regarding Tls configuration.
        Routine should invoke sed.usePsk to configure the chosen cipher suite.
        If usePsk is not invoked, TLS will not be configured.

        Parameters:
          sed             - The Sed instance for this device.
          cipherSuites    - list of available cipher suites to utilize listed in preferential order by the drive.
        '''
        pass


currentFuncName = lambda n = 0: sys._getframe(n + 1).f_code.co_name


class SedObject(object):

    def __init__(self, d):
        self.__dict__ = d

    def __repr__(self, *args, **kwargs):
        out = io.StringIO()
        keys = list(vars(self).keys())
        klen = max(len(k) for k in keys)
        for k in sorted(keys):
            v = str(getattr(self, k))
            if len(v) == 8 and v[0] == '\x00':  # UIDs
                v = "0x%016x" % (struct.unpack('>Q', v)[0])
            out.write('%*s:  %s\n' % (klen, k, v))
        result = out.getvalue()
        out.close()
        return result


class Sed(pysed.Sed):
    '''
    classdocs
    Establishes communications to the SED functionality of a drive.

    All methods return False on error.  Methods may return an object upon success or otherwise True

    Many methods have an optional parameter authAs.  This parameter provides the authority to
    authenticate as and credentials.  The parameter may take many forms:
    string - Converted to Authority, if not a valid authority string, assumed to be plaintext credentials.
    object - Assumed to be a container for the credential.  Object has a plainText property
        that extracts the credentials.
    tuple - Assumed to be (auth, cred).  if auth is not a valid authority string, assumed to be
        plaintext credential.  cred is either a string or a Credential message.  In the string
        form, assumed to be a plaintext credential.
    If authority or credentials are not provided, the callbacks class methods provided at construction
    will be consulted.

    Caller must have CAP_SYS_RAWIO priveleges to communicate.  Access to /dev/sdxx requires
    the caller to either have CAP_DAC_OVERRIDE or be in the 'disk' (EL) supplimental group.
    Full reset logic also requires CAP_SYSADM for rights to reset the drive.
    '''

    def __init__(self, dev, **kwargs):
        '''
        Constructor
          dev         - the device name of the storage device
                      - May also be the wwn in numeric or string form.
        Named Parameters:
          callbacks   - A class that handles the methods in the SedCallbacksStub class
        '''
        self.callbacks = kwargs.get('callbacks', SedCallbacksStub)
        if isinstance(self.callbacks, type):
            self.callbacks = self.callbacks(**kwargs)
        if hasattr(self.callbacks, 'logger'):
            kwargs['logger'] = self.callbacks.logger
        else:
            warnings.warn("Logger not initialized and passed into the TCGAPI")

        if isinstance(dev, int):
            dev = hex(dev)
        if '/' not in dev:
            if dev[0].isdigit():
                if dev[1] != 'x':
                    dev = '0x' + dev
                dev = "/dev/disk/by-id/wwn-" + dev

        super(Sed, self).__init__(dev, pysedSupport.getUidTables, PskCipherSuites, kwargs)

        self.token = {}
        if hasattr(tcgSupport, 'configureTls'):
            cipherSuites = self._cipherSuites()
            if cipherSuites is not None:
                tcgSupport.configureTls(self, [PskCipherSuites.Name(s) for s in cipherSuites])

    def close(self, authAs=None):
        '''
        Shutdown communication to the SED drive.
        authAs - authority to use to write dirty DataStore data if necessary
        Support provided only for Enterprise drives.
        '''
        if self.callbacks.dataStore is not None:
            self.writeData(authAs=authAs)

    def _getAuthAs(self, authAs, defAuth=None):
        '''
        Normalize the authAs parameter into a (auth, cred) tuple.

        Parameters:
          authAs    - The authAs parameter to the function being performed.
        Optional named parameters:
          defAuth   - The authority to utilize in case no authority was supplied.

        Returns a tuple containing the authority and credential to be used to authenticate.
        '''
        if authAs is None:
            authAs = (None, None)
        elif isinstance(authAs, tuple):
            auth, cred = authAs[:]
            authAs = (auth, cred)
        else:
            tcgSupport.fail(msg='Unknown authAs parameter type: ' + str(authAs))

        if not isinstance(authAs, tuple):
            tcgSupport.fail(msg='authAs parameter normalization error: ' + str(authAs))

        auth, cred = authAs[:]
        if auth is None:
            if defAuth:
                auth = defAuth
            else:
                if hasattr(self.callbacks,'logger'):
                    tcgSupport.getAuth(self.callbacks.logger,currentFuncName(1), defAuth)

        if auth == 'Anybody':
            return auth

        if cred is None:
            if hasattr(self.callbacks,'keymanager'):
                cred = tcgSupport.getCred(self.callbacks.keymanager,auth)
            else:
                print ("Credentials not provided for the method"+' '+currentFuncName(1))

        return (auth, cred)

    def _failedCredentials(self, auth, cred):
        '''
        Callback from the base class to alert us of a failed authentication and a chance to
        provide the correct credentials.
        Parameters:
          auth - The authority being authenticated.  A string.
          cred - The credentials supplied to invoke() or returned from a
                 previous callback of this method.
        '''
        if hasattr(self.callbacks,'logger'):
            return tcgSupport.failedCred(self.callbacks.logger,auth, cred)

    def fail(self, msg, status):
        '''
        Callback for a failed operation.
        msg - message to be displayed.
        status - Status of the operation being performed
        '''
        if hasattr(self.callbacks,'logger'):
            return tcgSupport.fail(self.callbacks.logger,self.callbacks.devname,StatusCode,op=currentFuncName(1), msg=msg, status=status)

    def getRange(self, rangeNo, auth, authAs=None):
        '''
        Reads a band from the drive.

        Parameters:
          rangeNo - the band to read
          auth    - Default auth in case if authAs is None

        Optional named parameters:
          authAs - tuple of authority, credential, or AuthAs structure.  Defaults to (Anybody)

        Returns a Range object with values read.  Attributes of this object are
        reflected from  the names as specified in the TCG specification.
        Consult setRange named parameters for attribute definitions.
        '''

        status, rv, kwrv = self.invoke('Band%d' % rangeNo, 'Get',
            authAs=self._getAuthAs(authAs, auth))

        if status != StatusCode.Success:
            return self.fail(rv, status)
        
        str_kwrv = tcgSupport.convert(kwrv)
        
        if len(str_kwrv) == 0:
            return None, True
        if self.SSC != 'Enterprise':
            for key in list(locking_table.keys()):
                str_kwrv[key] = str_kwrv[locking_table[key]]
            for key in list(str_kwrv.keys()):
                if not isinstance(key, str):
                    del str_kwrv[key]
        str_kwrv['LockOnReset'] = 0 in str_kwrv['LockOnReset']
        return SedObject(str_kwrv), True

    def setRange(self, auth, rangeNo, authAs=None, **kwargs):
        '''
        Modifies a bands fields. Support provided only for Enterprise and Opalv2.0

        Parameters:
          rangeNo         - The band to modify. (required)
          auth            - Default auth in case if authAs is None

        Optional named parameters:
          authAs          - Tuple of authority, credential, or AuthAs structure.
          RangeStart      - The starting LBA of the band.
          RangeLength     - The number of LBAs included in the band.
          ReadLocked      - Prohibit read access to the band (True) or allow read access to the band (False)
          ReadLockEnabled - Enable (True) ReadLocked field for this band.
          WriteLocked     - Prohibit write access to the band (True) or allow write access to the band (False)
          WriteLockEnabled- Enable (True) WriteLocked field for this band.
          LockOnReset     - Enable locks on power cycle (True) or do not modify locks on power cycle (False)
        '''
        for key, value in list(kwargs.items()):
            if key == 'LockOnReset':
                value = [0] if kwargs.get('LockOnReset') == str(True) else []
            self.token.update({key:value})
        arg = tcgSupport.tokens(self)
        status, rv, kwrv = self.invoke('Band%d' % rangeNo, 'Set', arg,
            authAs=self._getAuthAs(authAs, auth),
            **self.token)
        self.token.clear()
        if status != StatusCode.Success:
            return self.fail(rv, status)
        return True

    def enable_range_access(self, objectId, user, auth, authAs=None):
        '''
        Provides band access to users. Opal 2.0 specific method.

        Parameters:
        objectId         - Locking Range object value.
        user             - User to whom access needs to be provided.
        auth             - Default auth in case if authAs is None.

        Optional Parameters:
        authAs           - Tuple of authority, credential, or AuthAs structure.
        '''
        Userno = int(''.join(filter(str.isdigit, user)))
        if  Userno == 1:
            User = baseObjectIds['User##']
        else:
            User = baseObjectIds['User##'] + Userno
        status, rv, kwrv = self.invoke(objectId, 'Set', (1, [(3, [("\x00\x00\x0C\x05", struct.pack(">Q", User)), ("\x00\x00\x0C\x05", struct.pack(">Q", User)), ("\x00\x00\x04\x0E", 1)])]),
                            authAs=self._getAuthAs(authAs, auth),
                            noNamed=True,
                            useTls=True)
        if status != StatusCode.Success:
            return self.fail(rv, status)
        return True

    def get_MEK(self, rangeNo, auth, authAs=None):
        '''
        Obtain the Media Encrytion Key (MEK) UID for the range from the Locking Table Support provided only for Opal2.0.

        Parameters:
          rangeNo         - The band number. (required)
          auth            - Default auth in case if authAs is None

        Optional Parameters:
        authAs           - Tuple of authority, credential, or AuthAs structure
        '''
        status, rv, kwrv = self.invoke('Band%d' % rangeNo, 'Get', ([(3, 0x0A), (4, 0x0A)]),
            authAs=self._getAuthAs(authAs, auth),
            noNamed=True,
            useTls=True)
        if status != StatusCode.Success:
            return self.fail(rv, status)
        kwrv['K_AES_256_Range' + str(rangeNo) + '_Key_UID'] = kwrv.pop(list(kwrv.keys())[0])
        return SedObject(kwrv), True

    def erase(self, rangeNo, authAs=None):
        '''
        Erases a band. Support provided only for Enterprise.

        Parameters:
          rangeNo - the band to modify

        Optional parameters:
          authAs - tuple of authority, credential, or AuthAs structure.
        '''
        status, rv, kwrv = self.invoke('Band%d' % rangeNo, 'Erase',
            authAs=self._getAuthAs(authAs, 'EraseMaster'),
            noNamed=True)
        if status != StatusCode.Success:
            return self.fail(rv, status)
        return True

    def gen_key(self, range_key, auth, authAs=None):
        '''
        Performs a secure erase of the range. Support provided only for Opal2.0.

        Parameters:
          range_key - Key Object value as an hexadecimal number

        Optional parameters:
          authAs - tuple of authority, credential, or AuthAs structure.

        '''
        status, rv, kwrv = self.invoke(range_key, 'GenKey',
            authAs=self._getAuthAs(authAs, auth),
            noClose=True,
            noNamed=False,
            useTls=True)
        if status != StatusCode.Success:
            return self.fail(rv, status)
        return True

    def changePIN(self, auth, pin, authAs=None, obj=None):
        '''
        Modify credentials for an authority. Support provided only for Enterprise and Opalv2.0
        auth - An authority string or numeric value identifying the authority to modify.
        pin  - The new PIN to apply to this authority.
        authAs - tuple of authority, credential, or AuthAs structure.
        '''
        obj = auth if obj == None else obj
        self.token.update({'PIN':pin})
        arg = tcgSupport.tokens(self)
        status, rv, kwrv = self.invoke(obj, 'Set', arg,
            authAs=self._getAuthAs(authAs, auth),
            useTls=True,
            **self.token)
        self.token.clear()
        if status != StatusCode.Success:
            return self.fail(rv, status)
        return True

    def checkPIN(self, auth, pin):
        '''
        Validate credentials for an authority. Support provided only for Enterprise and Opalv2.0
        Parameters:
          auth - A Authority string or numeric value identifying the authority to modify.
          pin  - The PIN to validate.  May be a string or an object with the attribute 'plainText'.
        Returns True if successfully authenticated, False otherwise.  Does not invoke fail method.
        '''
        return self._checkPIN(auth, pin)

    def writeaccess(self, user, tableno, authAs=None):
        '''
         Provides DataStore Table write access to users. Opal 2.0 specific method.

        Parameters:
        user             - User to whom access needs to be provided.

        Optional Parameters:
        authAs           - Tuple of authority, credential, or AuthAs structure.
        '''
        if int(''.join(filter(str.isdigit, user))) == 1:
            User = baseObjectIds['User##']
        else:
            User = baseObjectIds['User##'] + int(''.join(filter(str.isdigit, user)))

        status, rv, kwrv = self.invoke('ACE_DataStore%d_Set_All' % tableno, 'Set',
                        (1, [(3, [("\x00\x00\x0C\x05", struct.pack(">Q", User))])]),
                        noNamed=True,
                        sp='LockingSP',
                        authAs=self._getAuthAs(authAs, 'Admin1'))
        if status != StatusCode.Success:
            return False
        return True

    def readaccess(self, user, tableno, authAs=None):
        '''
        Provides DataStore Table read access to users. Opal 2.0 specific method.

        Parameters:
        user             - User to whom access needs to be provided.

        Optional Parameters:
        authAs           - Tuple of authority, credential, or AuthAs structure.
        '''

        if int(''.join(filter(str.isdigit, user))) == 1:
            User = baseObjectIds['User##']
        else:
            User = baseObjectIds['User##'] + int(''.join(filter(str.isdigit, user)))

        status, rv, kwrv = self.invoke('ACE_DataStore%d_Get_All' % tableno, 'Set',
                        (1, [(3, [("\x00\x00\x0C\x05", struct.pack(">Q", User))])]),
                        noNamed=True,
                        sp='LockingSP',
                        authAs=self._getAuthAs(authAs, 'Admin1'))
        if status != StatusCode.Success:
            return False
        return True

    def readData(self, auth, authAs=None):
        '''
        Read the SED DataStore.  Data is available as the callback.dataStore attribute.
        Support provided only for Enterprise.
        Optional named parameters:
          authAs - tuple of authority, credential, or AuthAs structure.  Defaults to (Anybody).
        Returns the DataStore object of non-volatile values, None when datastore is empty, False on error.
        '''
        authAs = self._getAuthAs(authAs, auth)
        if self.checkPIN(authAs[0], self.mSID) == True:
            authAs = (authAs[0], self.mSID)
        if ''.join(re.split("[^a-zA-Z]+", auth)) == "User":
            name_value = ([(0o1, 00), (0o2, self.data_length)])
        else:
            name_value = [('startRow', 0)]

        status, rv, kwrv = self.invoke('DataStore', 'Get',
            name_value,
            sp='LockingSP',
            authAs=authAs,
            noNamed=True,
        )
        if status != StatusCode.Success:
            return self.fail(rv, status)
        elif len(rv) > 0:
            self.callbacks.dataStore = tcgSupport.fromSerialized(rv[0])
            return self.callbacks.dataStore
        return None

    def writeData(self, auth, data, authAs=None):
        '''
        Write the SED DataStore.
        Optional named parameters:
          authAs - tuple of authority, credential, or AuthAs structure.  Defaults to (BandMaster0, mSID).
                   Needs to authenticate as any BandMaster or EraseMaster.
        Returns True when data is written.
        Returns False if data is invalid or data is not dirty.
        '''

        authAs = self._getAuthAs(authAs, auth)
        if self.checkPIN(authAs[0], self.mSID) == True:
            authAs = (authAs[0], self.mSID)

        if ''.join(re.split("[^a-zA-Z]+", auth)) == "User":
            name_value, s_data = (00, 00), (0o1, tcgSupport.serialize(data))
        else:
            name_value, s_data = [('startRow', 0)], tcgSupport.serialize(data)

        status, rv, kwrv = self.invoke('DataStore', 'Set',
            name_value,
            s_data,
            sp='LockingSP',
            authAs=authAs,
            noNamed=True,
        )

        if status != StatusCode.Success:
            return self.fail(rv, status)
        return True

    def getPort(self, uid, authAs=None):
        '''
        Retrieve the port table for the specified port uid.Support provided only for Enterprise and Opalv2.0

        Parameters:
          uid - Port UID.  Port UIDs are enumerable through the ports attribute.

        Optional named parameters:
          authAs - tuple of authority, credential, or AuthAs structure.

        Returns a Port object with attributes reflected from the TCG object table fields.
        Consult setPort named parameters for attribute definitions.
        '''
        status, rv, kwrv = self.invoke(uid, 'Get',
            authAs=self._getAuthAs(authAs, 'SID')
        )
        if status != StatusCode.Success:
            return self.fail(rv, status)

        if len(kwrv) == 0:
            return None
        
        str_kwrv = tcgSupport.convert(kwrv)
        
        if self.SSC != 'Enterprise':
            for key, val in portlocking_table.items():
                str_kwrv[key] = str_kwrv[portlocking_table[key]]

        if 'LockOnReset' in str_kwrv:
            str_kwrv['LockOnReset'] = 0 in str_kwrv['LockOnReset']
        if 'PortLocked' in kwrv:
            str_kwrv['PortLocked'] = bool(str_kwrv['PortLocked'])
        if 'UID' in str_kwrv:
            str_kwrv['UID'] = uid
        return SedObject(str_kwrv)

    def setPort(self, port, authAs=None, **kwargs):
        '''
        Set the locked states of a port.Support provided only for Enterprise and Opalv2.0

        Optional named parameters:
          port         - The UID of the port to modify.
          authAs       - Tuple of authority, credential, or AuthAs structure.
          PortLocked   - The current locked state.  True: enabled, False: disabled, None: do not not change.
          LockOnReset  - Locked state upon reset. True: enabled, False: disabled, None: do not not change.
        '''
        currentFuncName = lambda n = 0: sys._getframe(n + 1).f_code.co_name
        for key, value in list(kwargs.items()):
            if key == 'LockOnReset':
                value = [0] if kwargs.get('LockOnReset') == True else []
            if key == 'PortLocked':
                value = 1 if kwargs.get('PortLocked') == True else 0
            self.token.update({key:value})
        arg = tcgSupport.tokens(self)
        status, rv, kwrv = self.invoke(port, 'Set', arg, sp='AdminSP',
            authAs=self._getAuthAs(authAs, 'SID'),
            **self.token)
        self.token.clear()
        if status != StatusCode.Success:
            return self.fail(rv, status)
        return True

    def getAuthority(self, auth, obj=None, authAs=None):
        '''
        Determines if an authority is enabled. Support provided only for Enterprise.

        Parameters:
          auth    -  An Authority string or numeric value identifying the authority to modify.
        Optional named parameters:
          obj     - Authority object on which the operation is being performed.Authority object on which the operation is being performed.
          authAs  - tuple of authority and credential.

        Returns True if the authority is enabled.
        '''
        status, rv, kwrv = self.invoke(obj, 'Get',
            authAs=self._getAuthAs(authAs, auth))
        if status != StatusCode.Success:
            return self.fail(rv, status)
    
        str_kwrv = tcgSupport.convert(kwrv)
        
        if str_kwrv.get('Enabled') == 1:
            return True
        else:
            return False

    def enableAuthority(self, auth, enable, obj=None, authAs=None):
        '''
        Enable/disable an authority.Support provided only for Enterprise and Opalv2.0

        Parameters:
          auth    - An authority string or numeric value identifying the authority to modify.
        Optional parameters:
          obj     - Authority object on which the operation is being performed.
          authAs  - tuple of authority, credential, or AuthAs structure.
        '''
        self.token.update({'Enabled':enable})
        arg = tcgSupport.tokens(self)
        status, rv, kwrv = self.invoke(obj, 'Set', arg,
            authAs=self._getAuthAs(authAs, auth),
            **self.token)
        self.token.clear()
        if status != StatusCode.Success:
            return self.fail(rv, status)
        return True

    def lockingInfo(self):
        '''
        Retrieve the LockingInfo table.  Attribute names are reflected from TCG table specification.
        Support provided only for Enterprise.
        Attributes include:
          - MaxRanges
          - EncryptSupport
          - LogicalBlockSize
          - LowestAlignedLBA
          - AlignmentGranularity
          - AlignmentRequired
          - MaxReEncryptions
          - KeysAvailableCfg
        '''
        status, rv, kwrv = self.invoke('LockingInfo', 'Get', sp='LockingSP')
        if status != StatusCode.Success:
            return self.fail(rv, status)
        
        str_kwrv = tcgSupport.convert(kwrv)
        
        return SedObject(str_kwrv)

    def random(self, count=32):
        '''
        Retrieve a string of random values from the drive's random number generator.
        Support provided only for Enterprise.

        count - number of bytes to generate.

        Returns a string containing the random string.
        '''
        st, a, kwa = self.invoke('ThisSP', 'Random', count, sp='AdminSP', noNamed=True)
        return a[0]

    def revert(self, psid):
        '''
        Reset SED configuration to factory settings.  This requires authenticating as the PSID.
        The credentials for the PSID are only available by print and QR on the drive label.

        psid   - May be the plain text credentials needed to authenticate as PSID.
                 May also be a table or class that returns the PSID credentials for a wwn index.

        Returns True when successful
        '''
        if isinstance(psid, str):
            creds = psid
        elif self.wwn in psid:
            creds = psid[self.wwn]
        elif hex(self.wwn) in psid:
            creds = psid[hex(self.wwn)]
        else:
            return False

        status, rv, kwrv = self.invoke('ThisSP', 'RevertSP',
            authAs=('PSID', creds),
            sp='AdminSP',
            timeout=5000,
            noNamed=True,
            noClose=True)
        if status != StatusCode.Success:
            return self.fail(rv, status)
        return True

    def revert_lockingSP(self, cred):
        '''
        Reverts the locking SP to factory state.Method exists only in Opal2.0.

        Parameters;
            cred - Admin1 Credentials

        Returns True when successful
        '''
        status, rv, kwrv = self.invoke('ThisSP', 'RevertSP',
            authAs=('Admin1', cred),
            sp='LockingSP',
            timeout=5000,
            noNamed=True,
            noClose=True,
            useTls=False)

        if status != StatusCode.Success:
            return self.fail(rv, status)
        return True

    def activate(self, auth, authAs=None):
        '''
        Activates the locking SP for the drive. Method exists only in Opal2.0.

        Parameters:
          auth    - An Authority string or numeric value identifying the authority to modify.
        Optional named parameters:
          authAs  - tuple of authority, credential, or AuthAs structure.

        '''
        status, rv, kwrv = self.invoke('LockingSP', 'Activate',
            authAs=self._getAuthAs(authAs, auth),
            sp='AdminSP',
            noNamed=True)

        if status != StatusCode.Success:
            return self.fail(rv, status)
        return True

    def tperSign(self, dataInput, authAs=None):
        '''
        Signs a payload with the drive's private key using the TPerSign.sign(dataInput) method.

        Parameters:
            - dataInput   - Up to 256 bytes payload to be signed by the drive's private key for certification.

        Returns the signed data in rv[0] when successful
        '''
        status, rv, kwrv = self.invoke('TPerSign', 'Sign', (dataInput),
            authAs=self._getAuthAs(authAs, 'Anybody'),
            sp='AdminSP',
            noNamed=True,
            timeout=5000)

        if status != StatusCode.Success:
            return self.fail(rv, status)
        return rv[0]

    def get_tperSign_cert(self, authAs=None):
        '''
        Retrieve the certificate used to sign the data from TPerSign method

        Parameters:
            - None

        Returns the public key certificate when successful in a bytearray
        that has been trimmed of its trailing 00 bytes value used for padding
        '''

        status, rv, kwrv = self.invoke('_CertData_TPerSign', 'Get', [],
            authAs=self._getAuthAs(authAs, 'Anybody'),
            sp='AdminSP',
            noNamed=True,
            timeout=5000)

        # If there is a failure go ahead and return the failure
        if status != StatusCode.Success:
            return self.fail(rv, status)

        # Take the return value output and trim any 00 byte padding from the end.
        # Make a bytearray copy of the rv and use it
        rv_bytes = bytearray(rv[0])

        # Start traversing the bytearray from the end. If we find a 0 value delete it from the bytearray
        # Do this until we find a value that is not zero and then just break out of the for loop.
        # We keep the rest of the data
        for i, element in reversed(list(enumerate(rv_bytes))):
                if element == 0:
                    del rv_bytes[i]
                else:
                    break

        return bytearray(rv_bytes)

    def getPskEntry(self, psk, authAs=None, sp='AdminSP'):
        '''
        Reads a PSK record from the drive.
        Used optionally to provide support for TLS Secure Messaging.

        Parameters:
          psk - the ordinate of the entry to read (integer), UID or previously retrieved TlsPsk object.

        Optional named parameters:
          authAs - tuple of authority, credential, or AuthAs structure.  Defaults to (Anybody)

        Returns a TlsPsk object with values read.  Attributes of this object are
        reflected from the names as specified in the TCG specification.
        Consult setPSK named parameters for attribute definitions.
        None is returned if the PSK entry is not supported.
        '''
        if isinstance(psk, int):
            psk = 'TLS_PSK_Key%d' % psk
        elif isinstance(psk, SedObject):
            psk = psk.Name
        status, rv, kwrv = self.invoke(psk, 'Get',
             authAs=self._getAuthAs(authAs, 'Anybody'), sp=sp)

        if status != StatusCode.Success:
            return self.fail(rv, status)
        
        if len(kwrv) == 0:
            return None
        
        str_kwrv = tcgSupport.convert(kwrv)
        
        if self.SSC == 'Opalv2':
            for key, val in c_tls_psk_table.items():
                str_kwrv[key] = str_kwrv[c_tls_psk_table[key]]
                
            for key in list(str_kwrv):
                if not isinstance(key, str):
                    del str_kwrv[key]

        if 'CipherSuite' in kwrv:
            str_kwrv['CipherSuite'] = PskCipherSuites.Name(str_kwrv['CipherSuite'])
        return SedObject(str_kwrv)

    def setPskEntry(self, psk, authAs=None, **kwargs):
        '''
        Modifies a TLS_PSK record for both SPs.
        Used optionally to provide support for TLS Secure Messaging.

        Parameters:
          psk  - the ordinate of the entry to write (integer), UID or previously retrieved TlsPsk object.
          auth - An Authority string or numeric value identifying the authority to modify.
        Optional named parameters:
           authAs        - List of Tuple of authority, credential, or AuthAs structure.
                            [(auth1,cred),(auth2,cred)]
          Enabled        - Determines if this key is enabled.
          PSK            - The preshared key.
          CipherSuite    - The TLS CipherSuite using this entry. One of the values in PskCipherSuites.
        '''
        if 'CipherSuite' in kwargs and (kwargs['CipherSuite'] is None or len(kwargs['CipherSuite']) > 2):
            kwargs['CipherSuite'] = PskCipherSuites.StringValue(kwargs['CipherSuite'])
        if isinstance(psk, int):
            psk = 'TLS_PSK_Key%d' % psk
        elif isinstance(psk, SedObject):
            psk = psk.Name
            if self.SSC == 'Opalv2':
                entry = int(psk[-1])
                psk = 'TLS_PSK_Key'+str(entry-1)

        self.token.update({'Enabled':kwargs.get('Enabled'), 'PSK':kwargs.get('PSK'), 'CipherSuite':kwargs['CipherSuite']})
        arg = tcgSupport.tokens(self)
        sps = ['AdminSP', 'LockingSP']

        for sp, authAs in zip(sps, authAs):
            authAs = (self._getAuthAs(authAs, authAs[0]))
            if self.checkPIN(authAs[0], self.mSID) == True:
                authAs = (authAs[0], self.mSID)
            status, rv, kwrv = self.invoke(psk, 'Set', arg,
                authAs=authAs, sp=sp,
                **self.token)
            if status != StatusCode.Success:
                return self.fail(rv, status)
        self.token.clear()
        return True
