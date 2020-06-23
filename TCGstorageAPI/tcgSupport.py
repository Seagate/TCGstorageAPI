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
# \file tcgSupport.py
# \brief Supports the implementation of TCG API
#-----------------------------------------------------------------------------
from pickle import loads, dumps
from passlib.utils.pbkdf2 import pbkdf2
import hmac
import hashlib
import struct

tokens_table= {'PIN':              [3],
              'RangeStart':        [3],
              'RangeLength':       [4],
              'ReadLockEnabled':   [5],
              'WriteLockEnabled':  [6],
              'ReadLocked':        [7],
              'WriteLocked':       [8],
              'LockOnReset':       [9,2],
              'Enabled':           [5,3],
              'PSK':               [4],
              'PortLocked' :       [3],
              'CipherSuite':       [5]}

locking_table={'UID':              0,
               'Name':             1,
               'CommonName':       2,
               'RangeStart':       3,
               'RangeLength':      4,
               'ReadLockEnabled':  5,
               'WriteLockEnabled': 6,
               'ReadLocked':       7,
               'WriteLocked':      8,
               'LockOnReset':      9}

portlocking_table={'UID':          0,
                   'Name':         1,
                   'LockOnReset':  2,
                   'PortLocked':   3}

c_tls_psk_table=  {'UID':          0,
                   'Name':         1,
                   'CommonName':   2,
                   'Enabled':      3,
                   'CipherSuite':  5}

def tokens(sed):
    '''
    The function to create the access handles for the tcgapi.

    Parameters:
        sed - SED device structure

    Returns:
        Returns numbered access specifier token in case of Opal and empty list in case of Enterprise.
    '''

    if sed.SSC== 'Enterprise':
        return []
    elif sed.SSC == 'Opalv2':
        token_values = [1,[]]
        for key,val in list(sed.token.items()):
            if key == 'LockOnReset' and "PortLocked" in sed.token or key=='Enabled' and 'CipherSuite' in sed.token:
                index = 1
            else:
                index = 0
            token_values[1].append((tokens_table[key][index],val))
        sed.token.clear()
        sed.token.update({'noNamed':True})
        return (tuple(token_values))

def configureTls(sed, cipherSuites):
        '''
        Request from pysed to configure TLS PSK.

        Tls is enabled if an entry using the most preferred cipher suite is enabled and
        we were able to determine the PSK.

        Parameters:
            sed - SED data structure of the drive
            cipherSuites- List of all cipherSuites supported by the drive
        '''
    
        sed.cipherSuite = cipherSuites[0]
        key = getPsk(sed)
        for entryId in range(4):
            psk = sed.getPskEntry(entryId)
            if psk is None:
                break
            if psk.Enabled == True and psk.CipherSuite == sed.cipherSuite and key is not None:
                sed.usePsk(psk.UID, sed.cipherSuite, key)
                return

def getPsk(sed):
    '''
    Read the PSK to use from the file system. The generated PSK is stored in a file and later read from the file.
    For the real life use case the file needs to be replaced with a key manager since storing the PSK in a file is not a safe practice.

    Parameters:
        sed - SED data structure of the drive
    '''
    try:
        with open("psk.txt",'rb') as f:
            psk = f.read()
    except IOError:
        psk = pbkdf2(hex(sed.wwn) + '7i92G*dp#' + sed.mSID, sed.random(), 6996, keylen=64)
        if psk is None:
            return None
        with open("psk.txt", "wb") as psk_file:
            psk_file.write(psk)
            psk_file.close()
    return psk

def serialize(nvdata):
    '''
    Return a serialized representation of the NVM data to be written to the SED DataStore.
    Parameters:
    nvdata - Non-volatile data to be stored on the datastore.

    '''
    ds = dumps(nvdata, 2)
    dsSign = 0x98ac9355
    iv = nvdata['iv']
    hash = hmac.new(iv, ds, hashlib.sha256).digest()
    packed_data = struct.pack('@2I32s', dsSign, len(ds), hash) + ds
    return packed_data

def fromSerialized(data):
    '''
    External use constructor.  Retrieve dataStore from data serialized from the SED DataStore.

   Returns: A DataStore object containing NVM data or fresh data if the dataStore was not retrieved
            None if empty, False on error.
    '''
    if len(data) == 0:
        return None
    ds = None
    sign, size, hash = struct.unpack_from('@2I32s', data)
    if sign == 0x98ac9355:
        try:
            pickled = data[40:size + 40]
            nvdata = loads(pickled)
            if hash == hmac.new(nvdata['iv'], pickled, hashlib.sha256).digest():
                return nvdata
            else:
                print("Failed to verify data returned from datastore")
                return False
        except EOFError:
            print("Failed to convert data to a python object")
            return False
    return None

def getCred(keymanager, auth):
    '''
    The function to get credential from the key manager class for the authority.

    Parametrs:
        auth - Authority for which a credential is needed.

    Returns:
        The credential for the authority.

    '''
    return keymanager.getKey(auth)

def failedCred(logger, auth, cred):
    '''
   Function invoked by to deal with wrong credential for an authority.

    Parameters:
        auth - authroity
        cred - Credential for the authority.
    '''
    msg = 'Invalid credentials'
    logger.error(msg)

def getAuth(logger, op, defauth=None):
    '''
    Function invoked by tcgapi to obtain the authority for the operation being performed.

    Parameters:
        op - operation being performed
        defauth - Default authority for the operation.
    '''
    if defauth is None:
        msg = 'Please provide the authority for' + '' + op
        logger.error(msg)
    return

def fail(logger,devname,StatusCode,msg=None, op=None, status=None):
    '''
    Function invoked by tcgapi in case of failure of operations

    Parameters:
        msg - Message to be logged
        op  - Operation being performed
        status - Status of the operation being performed.
    '''
    lmsg = ''
    lmsg += devname + ' '
    if isinstance(msg, str):
        lmsg += msg + '\n'
    if op is not None:
        lmsg += 'Failed SED operation {0}: {1} '.format(op, StatusCode.values[status])
    logger.error(lmsg)

def convert(data):
    '''
    Function invoked by tcgapi to convert bytes to string
    
    Parameters:
    data - data in bytes
    
    Returns data as string 

    '''
    if isinstance(data, bytes):  
        try:
            val = data.decode()
            if val.isprintable() == True:
                return val
            else:
                return data.hex()
        except:
            hex_str = data.hex()
            hex_int= int(hex_str, 16)
            return hex(hex_int)
    if isinstance(data, dict):   
        return dict(map(convert, data.items()))
    if isinstance(data, tuple):  
        return tuple(map(convert, data))
    if isinstance(data, list):   
        return list(map(convert, data))
    return data
