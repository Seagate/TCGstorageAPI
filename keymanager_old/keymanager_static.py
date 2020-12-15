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

class Static(KeyManager):
    '''
    This is a class to store authority and credentials temporarily.
    '''

    def __init__(self):
        '''
        The function to create a structure for authority and credentials.
        '''
        self.credentials = {}

    def getKey(self,auth):
        '''
        The function to get the credential value for an authority.

        Parameters:
            auth -Authority
        Returns:
            cred - credential
        '''

        cred = self.credentials[auth]
        return cred
    
    @abstractmethod
    def addKey(self):
        pass

    def setKey(self,auth,cred):
        '''
        The function to set credential for an authority.

        Parameters:
            auth - Authority
            cred - credential
        '''

        self.credentials[auth]=cred
        return
