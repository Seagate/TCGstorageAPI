#----------------------------------------------------------------------------
# Do NOT modify or remove this copyright
#
# Copyright (c) 2020-2021 Seagate Technology LLC and/or its Affiliates
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

from .keymanager_abstract import KeyManager
import json
import os
import random

class keymanager_json(KeyManager):
    def __init__(self):
        pass

    def storePasswords(self, wwn, cred_table):
        jsonFilename = '{}.json'.format(wwn)
        with open(jsonFilename, 'w+') as json_file:
            json_file.write(json.dumps(cred_table))

    def getPasswords(self, wwn):
        jsonFilename = '{}.json'.format(wwn)
        # Get the passwords from a json file (if exists)
        if os.path.isfile(jsonFilename):
            with open(jsonFilename) as json_file:
                cred_table = json.load(json_file)

        # Else, return an empty dictionary
        else:
            cred_table = dict()

        return cred_table

    def deletePasswords(self, wwn):
        jsonFilename = '{}.json'.format(wwn)
        if os.path.isfile(jsonFilename):
            os.remove(jsonFilename)

    def getBandNames(self, wwn):
        jsonFilename = '{}.json'.format(wwn)
        bandList = list()
        cred_table = self.getPasswords(wwn)
        for keyName in list(cred_table.keys()):
            if 'User' in keyName:
                bandList.append(keyName)
            if 'BandMaster' in keyName:
                bandList.append(keyName)
        return bandList

    def setKey(self, wwn, key, value):
        cred_table = self.getPasswords(wwn)
        cred_table[key] = value
        self.storePasswords(wwn, cred_table)
    
    def getKey(self, wwn, key):
        cred_table = self.getPasswords(wwn)
        return cred_table[key]

    def deleteKey(self, wwn, key):
        failureStatus = False
        cred_table = self.getPasswords(wwn)
        cred_table.pop(key, None)
        failureStatus = self.storePasswords(wwn, cred_table)
        return failureStatus

    def getWWNs(self):
        WWN_list = list()
        for item in os.listdir():
            if item[-5:] == '.json':
                WWN_list.append(item[:-5])
        return WWN_list

    def generateRandomValue(self):
        return '%032x' % random.randrange(16**32)
