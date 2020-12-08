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
# \file keymanager.py
# \brief Defines KeyManager Class
#
#-----------------------------------------------------------------------------
from .keymanager_abstract import KeyManager

import requests
import json
import os
import string
import random

# Helper function to retrieve the value 
def format(resp, k1, k2):

    data = resp.json()
    for key in data:
        if key == k1:
            for k, v in data[key].items():
                if k == k2:
                    return (data[key][k])
                
class Vault(KeyManager):

    def __init__(self, dev,hostname, fqdn, port):
        '''
        hostname : The host name to connect to
        fqdn : The fully Qualified Domain Name of the server
        port : The port number
        server_cert : The path to the server certificate for TLS verification
        client_cert : The path to the client certificate for authorization
        client_key : The path to client key for authorization
        '''
        
        self.server_cert = os.getcwd() + '/certs/super7-vault-ramallo-intermediate.pem'
        self.client_cert = os.getcwd() + '/certs/c1n1-tharthar-tls.pem'
        self.client_key = os.getcwd() + '/certs/c1n1-tharthar-tls.key'
        self.url = fqdn + ':' + str(port)
        self.hostname = hostname
        self.dev = dev
        self.cred_table = {
        'SID':          '',
        'C_PIN_Admin1': '',
        'Admin1':       '',
        'C_PIN_User1':  '',
        'User1'      :  '',
        'User2'      :  '',
        'C_PIN_User2':  '',
        'EraseMaster':  '',
        'BandMaster0':  '',
        'BandMaster1':  '',
        'BandMaster2':  ''}
        for key in self.cred_table:
            self.cred_table[key] =  self.generate_random_password()

        resp = requests.post(self.url + '/v1/auth/cert/login', verify=self.server_cert, data={"name": self.hostname}, cert=(self.client_cert, self.client_key))
        
        try :
            resp.raise_for_status()
        except requests.exceptions.RequestException as e:
            raise SysstemExit(e)
        
        # Generate a new token for further authentication to Vault
        self.vault_token = format(resp, 'auth', 'client_token')
        self.headers = {"X-Vault-Token":self.vault_token}
        
     # Helper funtion to generate a random password
    def generate_random_password(self):

        chars = string.ascii_uppercase + string.ascii_lowercase + string.digits
        size = random.randint(14, 19)
        return ''.join(random.choice(chars) for x in range(size))
 
    # Post a secret to the Vault server
    def addKey(self):
        '''
        dev - The device handle to operate on 
        '''

        self.secret = json.dumps({"data": self.cred_table})
        print(self.url + '/v1/secret/data/' + self.hostname + '/' + self.dev)
        try :
            requests.post(self.url + '/v1/secret/data/' + self.hostname + '/' + self.dev, data=self.secret, headers=self.headers, verify=self.server_cert)
        except requests.exceptions.RequestException as e:
            raise SystemExit(e)

    # Retrieve the secret from the Vault server
    def getKey(self, auth):
        '''
        dev - The device handle to operate on 
        auth - The authority to retrieve the PIN for
        '''

        try :
            resp = requests.get(self.url + '/v1/secret/data/' + self.hostname + '/' + self.dev, headers=self.headers, verify=self.server_cert)
        except requests.exceptions.RequestException as e:
            raise SystemExit(e)
        val = format(resp,'data','data')
        return val[auth]
    
    def setKey(self,key,value):
        pass
    