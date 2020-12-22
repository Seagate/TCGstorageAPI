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
            config_table = { 'server': '', 'container': '', 'root_token': ''}
            with open(configfile, 'w+') as json_file:
                json_file.write(json.dumps(config_table))
            print('Vault configuration file not found at {}'.format(configfile))
            print('Created a default file, please enter Vault Details')
            sys.exit(1)

        self.server = config_table['server']
        self.container = config_table['container']
        self.root_token = config_table['root_token']
        self.header = {'X-Vault-Token': '{}'.format(self.root_token)}

    def storePasswords(self, wwn, cred_table):
        url = self.server + self.container + '/' + wwn
        response = requests.post(url, headers=self.header, data=cred_table)
        if not response.ok:
            print("Error {} on POST request to {}".format(response.status_code, url))

    def getPasswords(self, wwn):
        secret = ''
        url = self.server + self.container + '/' + wwn
        response = requests.get(url, headers=self.header)
        if not response.ok:
            print("Error {} on GET request to {}".format(response.status_code, url))
            if response.status_code:
                print("If enrolling a new drive, this 404 is expected")
        else:
            secret = json.loads(response.text)['data']
        return secret

    def getKey(self, wwn, key):
        try:
            value = self.getPasswords(wwn)[key]
        except KeyError:
            print("Unable to retrieve value for {}".format(key))
            value = ''
        return value

    def setKey(self, wwn, key, value):
        cred_table = self.getPasswords(wwn)
        if cred_table:
            cred_table[key] = value
        else:
            cred_table = {key: value}
        self.storePasswords(wwn, cred_table)

    def generateRandomValue(self):
        secret = ''
        url = self.server + 'sys/tools/random'
        random_info = {"bytes": 16, "format": "hex"}
        response = requests.post(url, headers=self.header, data=random_info)
        if not response.ok:
            print("Error {} on POST request to {}".format(response.status_code, url))
        else:
            secret = json.loads(response.text)['data']['random_bytes']
        return secret