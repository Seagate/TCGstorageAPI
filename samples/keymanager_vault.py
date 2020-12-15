import json
import os
import random
import requests

wwn = '5000C50038423737'

class Vault(object):
    def __init__(self, server, container):
        
        #server = 'http://10.1.156.120:8200/v1/'
        self.server = server
        #container = 'SeagateSecure'
        self.container = container
        self.root_token = 's.J90j2JEtsKtvoHNtd6Qi5rvv'
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
        else:
            secret = json.loads(response.text)['data']
        return secret

    def getKey(self, wwn, key):
        return self.getPasswords(wwn)[key]

    def setKey(self, wwn, key, secret):
        cred_table = self.getPasswords(wwn)
        if cred_table:
            cred_table[key] = secret
        else:
            cred_table = {key: secret}
        self.storePasswords(wwn, cred_table)

    def generateRandomValue(self):
        return '%032x' % random.randrange(16**32)