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

from abc import ABC, abstractmethod
import random
 
class KeyManager(ABC):
 
    def __init__(self):
        self.value = value
        super().__init__()
    
    @abstractmethod
    def storePasswords(self, wwn, cred_table):
        pass

    @abstractmethod
    def getPasswords(self, wwn):
        pass

    @abstractmethod
    def setKey(self, wwn, key, value):
        pass
    
    @abstractmethod
    def getKey(self, wwn, key):
        pass
    
    @abstractmethod
    def generateRandomValue(self):
        pass
