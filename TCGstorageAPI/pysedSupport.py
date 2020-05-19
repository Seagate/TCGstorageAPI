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
# ****************************************************************************
#
# \file pysedSupport.py
# \brief Supports TCGAPI implementation
#
#-----------------------------------------------------------------------------

'''
Tables for use by the pysed module specifying various UUIDs defined by the TCG specification.
'''
import string
import re

class LookupIds(object):
    baseTable = None

    def __getitem__(self, name):
        try:
            return self.baseTable[name]
        except KeyError:
            pass

        count = int(''.join(filter(str.isdigit,name)))
        table_element = re.sub(str(count),'##',name)
        try:
            return self.baseTable[table_element] + count
        except KeyError:
            pass

baseSPIds = {
    "AdminSP":          0x0000020500000001,
    "LockingSP":        0x0000020500010001,
    "ThisSP":           1,
    }

baseMethodIds = {
    "Get":              0x0000000600000006,
    "Set":              0x0000000600000007,
    "Next":             0x0000000600000008,
    "Authenticate":     0x000000060000000C,
    "RevertSP":         0x0000000600000011,
    "Revert":           0x0000000600000202,
    'Random':           0x0000000600000601,
    'Erase':            0x0000000600000803,
    'Sign':             0x000000060000060F,
    'Activate':         0x0000000600000203,
}

baseAuthIds = {
    "Anybody":          0x0000000900000001,
    "EraseMaster":      0x0000000900008401,
    "SID":              0x0000000900000006,
    "Makers":           0x0000000900000003,
    "PSID":             0x000000090001FF01,
    'BandMaster##':     0x0000000900008001,
    "User##":           0x0000000900030000,
    "Admin1":           0x0000000900010001,
}

adminAuths = [ baseAuthIds[n] for n in ('SID', 'Makers', 'PSID','Anybody')]

baseObjectIds = {
    "ThisSP":           1,
    "AdminSP":          0x0000020500000001,
    "LockingSP":        0x0000020500000002,
    'Admin1':           0x0000000b0001000,
    'User##':           0x0000000900030000,
    "Table":            0x0000000100000001,
    "LockingInfo":      0x0000080100000000,
    "Band##":           0x0000080200000001,
    'DataStore':        0x0000800100000000,
    "MSID":             0x0000000B00008402,
    'SID':              0x0000000b00000001,
    'EraseMaster':      0x0000000b00008401,
    'BandMaster##':     0x0000000b00008001,
    # C_PIN Columns
    'C_PIN_SID':           0x0000000900000001,# C_PIN_Object
    'C_PIN_EraseMaster':   0x0000000900008401,
    'C_PIN_BandMaster##':  0x0000000900008001,
    'Makers':              0x0000000900000003,
    'C_PIN_Admin1':        0x0000000B00010001,
    'C_PIN_User##':        0x0000000B00030000,
    'SOM':                 0x0001000700000000,
    'TLS_PSK_Key##':       0x0000001e00000001,
    'TPerSign':            0x0000000900000007,
    '_CertData_TPerSign':  0x0001000400000000,
    'ACE_Locking_Range##_Set_RdLocked':0x000000080003E000,
    'ACE_Locking_Range##_Set_WrLocked':0x000000080003E800,
    'ACE_DataStore##_Set_All':   0x000000080003FC01,
    'ACE_DataStore##_Get_All':   0x000000080003FC00
}

class SPIds(LookupIds):
    def __init__(self, sed=None):
        if (sed.SSC == 'Opalv2'):
            baseSPIds.update({"LockingSP":0x0000020500000002})
        SPIds.baseTable = baseSPIds

class MethodIds(LookupIds):
    def __init__(self, sed=None):
        if (sed.SSC == 'Opalv2'):
            baseMethodIds.update({"Get":0x0000000600000016, "Set":0x0000000600000017, "Authenticate":0x000000060000001C})
        MethodIds.baseTable = baseMethodIds

class ObjectIds(LookupIds):
    def __init__(self, sed=None):
        if (sed.SSC == 'Opalv2'):
            baseObjectIds.update({'Band##':0x0000080200030000,'DataStore':0x0000100100000000})
        ObjectIds.baseTable = baseObjectIds

class AuthIds(LookupIds):
    baseTable = baseAuthIds

def getSp(obId, authId):
    '''
    Figure out the default SP from the upper 32-bits of the object ID
    as dictated by TCG Core 2.0 Table 237.
    If not conclusive, figure out the SP from the authId.
    '''
    sp = None
    prefix = obId >> 32;
    if prefix > 0x801 and prefix < 0xa00:
        sp = 'LockingSP'
    elif (prefix > 0x201 and prefix < 0x400) or authId in adminAuths:
        sp = 'AdminSP'
    elif authId != baseAuthIds['Anybody']:
        sp = 'LockingSP'
    if sp is not None:
        return baseSPIds[sp]
    return 0;

def getUidTables(sed):
    '''
    Retrieve Uid dictionaries.  Dictionaries use a string as an index and return the Uid
    as an integer.  Four dictionaries are returned to translate SP, Authorities, Objects and Methods.
    This could be expanded for other SSC's to interrogate tables stored on the Sed.
    '''

    return SPIds(sed), AuthIds(), ObjectIds(sed), MethodIds(sed), getSp
