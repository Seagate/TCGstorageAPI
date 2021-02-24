#----------------------------------------------------------------------------
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

from .keymanager_abstract import KeyManager
import json
import os
import random
import requests
import sys

class keymanager_vault(KeyManager):
    def __init__(self, configfile):
        
        try:
            with open(configfile) as json_file:
                config_table = json.load(json_file)

        except FileNotFoundError:
            config_table = { 'server': '', 'token': ''}
            with open(configfile, 'w+') as json_file:
                json_file.write(json.dumps(config_table))
            print('Vault configuration file not found at {}'.format(configfile))
            print('Created a default file, please enter Vault Details')
            sys.exit(1)

        self.server = config_table['server'] + 'v1/'
        self.container = 'SeagateSecure'
        self.token = config_table['token']
        self.header = {'X-Vault-Token': '{}'.format(self.token)}

    def hasPermission(self, key):
        hasPermission = False
        url = self.server + 'sys/capabilities'
        data = {'token': self.token, 'path': 'SeagateSecure/+/{}'.format(key)}
        response = requests.put(url, data=data, headers=self.header)
        if response.ok:
            if json.loads(response.text)['capabilities'] != ['deny']:
                hasPermission = True
        return hasPermission

    def deletePasswords(self, wwn):
        failureStatus = False
        if not self.hasPermission('SID'):
            print('Provided token does not have permissions for deletePasswords')
            failureStatus = True
        else:
            url = self.server + self.container + '/' + wwn + '?list=true'
            response = requests.get(url, headers=self.header)
            try:
                all_list = json.loads(response.text)['data']['keys']
            except KeyError:
                all_list = list()
            for item in all_list:
                url = self.server + self.container + '/' + wwn + '/' + item
                response = requests.delete(url, headers=self.header)
                if not response.ok:
                    print("Unexpected {} error".format(response.status_code))
                    print(response.text)
                    failureStatus = True
        return failureStatus

    def getBandNames(self, wwn):
        bandList = list()
        url = self.server + self.container + '/' + wwn + '?list=true'
        response = requests.get(url, headers=self.header)
        try:
            all_list = json.loads(response.text)['data']['keys']
        except KeyError:
            all_list = list()
        for keyName in all_list:
            if 'User' in keyName:
                bandList.append(keyName)
            if 'BandMaster' in keyName:
                bandList.append(keyName)
        return bandList

    def getKey(self, wwn, key):
        secret = ''
        if not self.hasPermission(key):
            print('Provided token does not have permissions for {}'.format(key))
            failureStatus = True
        else:
            url = self.server + self.container + '/' + wwn + '/' + key
            response = requests.get(url, headers=self.header)
            if not response.ok:
                print("Unexpected {} error".format(response.status_code))
                print(response.text)
            else:
                secret = json.loads(response.text)['data']['value']
        return secret

    def setKey(self, wwn, key, value):
        failureStatus = False
        if not self.hasPermission(key):
            print('Provided token does not have permissions for {}'.format(key))
            failureStatus = True
        else:
            url = self.server + self.container + '/' + wwn + '/' + key
            cred_table = {'value': value}
            response = requests.post(url, headers=self.header, data=cred_table)
            if not response.ok:
                print("Error {} on POST request to {}".format(response.status_code, url))
                print(response.text)
                failureStatus = True
        return failureStatus

    def deleteKey(self, wwn, key):
        failureStatus = False
        if not self.hasPermission(key):
            print('Provided token does not have permissions for {}'.format(key))
            failureStatus = True
        else:
            url = self.server + self.container + '/' + wwn + '/' + key
            response = requests.delete(url, headers=self.header)
            if not response.ok:
                print("Unexpected {} error".format(response.status_code))
                print(response.text)
                failureStatus = True
        return failureStatus

    def getWWNs(self):
        url = self.server + self.container + '?list=true'
        response = requests.get(url, headers=self.header)
        try:
            WWN_list = json.loads(response.text)['data']['keys']
        except KeyError:
            WWN_list = list()
        return WWN_list

    def generateRandomValue(self):
        secret = 0
        url = self.server + 'sys/tools/random'
        random_info = {"bytes": 16, "format": "hex"}
        response = requests.post(url, headers=self.header, data=random_info)
        if not response.ok:
            print("Error {} on POST request to {}".format(response.status_code, url))
        else:
            secret = json.loads(response.text)['data']['random_bytes']
        return secret