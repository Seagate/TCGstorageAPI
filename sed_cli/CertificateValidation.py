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
# \file CertificateValidation.py
# \brief Utility file for sed_cli.py
#        Note: this functionality is not supported on all SEDs
#
#-----------------------------------------------------------------------------
import re
import string
import urllib.request, urllib.error, urllib.parse
import os
from ssl import DER_cert_to_PEM_cert
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from OpenSSL import crypto
from cryptography.hazmat.backends import default_backend
import mimetypes

import re
import string
import urllib.request, urllib.error, urllib.parse
import os
from ssl import DER_cert_to_PEM_cert
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from OpenSSL import crypto
from cryptography.hazmat.backends import default_backend
import mimetypes
from TCGstorageAPI import tcgSupport

class VerifyIdentity(object):
    """
    This is a class for performing device certificate and signature validation
    Attributes:
    cert: Certificate pulled from the device
    """

    def __init__(self,cert):
        self.drive_cert = cert

    def validate_drive_cert(self):
        '''
        The function to perform drive certificate validation.
        '''
         ##Lambda function to verify the content of the certificate. If the certificate encoding is binary it can assigned as der type else PEM
        textchars = bytearray({7,8,9,10,12,13,27} | set(range(0x20, 0x100)) - {0x7f})
        is_binary_string = lambda bytes: bool(bytes.translate(None, textchars))  
        driveCert_PEM = DER_cert_to_PEM_cert(bytes(self.drive_cert))
        
        self.x509 = crypto.load_certificate(crypto.FILETYPE_PEM, DER_cert_to_PEM_cert(bytes(self.drive_cert)))
        subject_name = self.x509.get_subject()
        self.CN = subject_name.CN
        trusted_certs = [driveCert_PEM]
        issuerCN_name = ''
        cert = self.drive_cert

        while('Root' not in issuerCN_name):
            if isinstance(cert, bytes):
                certi=open(cert_filename, 'rb').read()
            elif isinstance(cert, bytearray):
                certi=DER_cert_to_PEM_cert(bytes(self.drive_cert))
            try:
                x509_info = crypto.load_certificate(crypto.FILETYPE_PEM,certi) 
            except:
                x509_info = crypto.load_certificate(crypto.FILETYPE_ASN1,certi) 
                
            issuer_name = x509_info.get_issuer()
            issuerCN_name = issuer_name.CN
            cert_filename = self.find_certificate_parent(cert)
            cert_binary = self.read_der_cert(cert_filename)
            cert = cert_binary
            cert_PEM = DER_cert_to_PEM_cert(bytes(cert_binary)) if is_binary_string(cert_binary) else bytes(cert_binary)
            trusted_certs.append(cert_PEM)
        
        verified = self.verify_chain_of_trust(driveCert_PEM, trusted_certs)

        if verified:
            print ("Drive Certificate chain verified from drive to root")
        else:
            raise Exception("ERROR: Issue verifying Certificate chain, do NOT trust")

    def validate_signature(self,original_string,signature):
        '''
        The function to validate the digital signature of the drive
        Parameters:
        original_string : The string being signed
        signature: The signature of the drive
        '''
        try:
            crypto.verify(self.x509,signature,original_string,'sha256')
            print("Drive signature verified successfully")
            return True
        except crypto.Error:
            print("Failed to verify signature of the drive")
            return False
        except:
            print("Failed to perform signature validation")
            return False

    @staticmethod
    def find_certificate_parent(child_certificate):
        '''
        Method used to find the parent certificates from the drive certificate that has been extracted.
        It looks for the issuer's URI line to download the certificate from drivetrust.seagate.com
        If it does not pull from the trusted website then it fails to add the certificate in.
        NOTE: It currently does not verify the issuer and subject chain.
        That is TBD and the proper way to do it. Still looking into how to implement.
        '''
        ##Lambda function to verify the content of the certificate. If the certificate encoding is binary it can assigned as der type else PEM
        textchars = bytearray({7,8,9,10,12,13,27} | set(range(0x20, 0x100)) - {0x7f})
        is_binary_string = lambda bytes: bool(bytes.translate(None, textchars))

        c_cert = x509.load_der_x509_certificate(bytes(child_certificate), default_backend()) if is_binary_string(child_certificate) else x509.load_pem_x509_certificate(bytes(child_certificate), default_backend())
        for ext in c_cert.extensions:
            # Look for the Certificate Extension that lists the Issuer Certificate URL
            str_ext = str(ext)
            if "authorityInfoAccess" in str_ext or "cRLDistributionPoints" in str_ext:
                split_ext = re.split(',', str_ext)
                for element in split_ext:
                    if "CRLDistributionPoints" in element or "access_location" in element:
                        if 'access_location' in element:
                            value_str = re.search(r'\((.*?)\)', element).group(1)
                        if "CRLDistributionPoints" in element:
                            value_str = re.search(r'\((.*?)\)', element).group(1)
                            value_str = value_str.split("=")
                            for val in value_str:
                                if 'http' in val:
                                    value_str = val
                                    break
    

                        web_url_str_1 = str.replace(value_str, "value=", '')
                        # Newer version of pyOpenSSL adds a u' to the http string in value=
                        # Need to check for it and strip it out along with ending single quote
                        web_url_str_2 = str.replace(web_url_str_1, "u\'", '')
                        web_url_str = str.replace(web_url_str_2, "\'", '')                        
                        web_url_list= web_url_str.split('/')
                        for i,element in enumerate(web_url_list):
                            if element == 'crl':
                                web_url_list[i]='cert'
                            elif '.crl' in element:
                                cer_ext = web_url_list[i].split('.')
                                for j,sol in enumerate(cer_ext):
                                    # Special case to handle the DTroot certificate 
                                    if sol == 'DTRoot1':
                                        cer_ext[j] ='DTRoot'
                                    if sol == 'crl':
                                        cer_ext[j]='cer'
                                        break
                                web_url_list[i] = '.'.join(cer_ext)
        
                        web_url_str ='/'.join(web_url_list) 

                        # Test to make sure the web_url_str is trusted
                        if "drivetrust.seagate.com" in web_url_str:
                            # This is a trusted Seagate website
                            # Split the string to get the Certificate filename to download
                            web_url_str_split = re.split('/', web_url_str)
                            for name in web_url_str_split:
                                if ".cer" in name:
                                    cert_filename = name
                            # Download the Certificate File
                            attempts = 0
                            while attempts < 3:
                                try:
                                    response = urllib.request.urlopen(web_url_str, timeout=5)
                                    content = response.read()
                                    CERT__FILENAME = os.path.join(cert_filename)
                                    f = open(CERT__FILENAME, 'wb')
                                    f.write(content)
                                    f.close()

                                    # Returning the filename for the certificate file that was downloaded.
                                    return cert_filename

                                except urllib.error.URLError as e:
                                    attempts += 1
                                    print(e.args)
                        else:
                            # The URL listed is not a trusted url.
                            print("ERROR: The URL provided by Certificate is not a trusted Website")
                            break
                       
            else:
                pass

        # The URL for the drive certificate parent was not found if we get this far...
        print("ERROR: The URL for the drive certificate parent was not found or is not trusted")

    @staticmethod
    def read_der_cert(filename):
        '''
        Method used to read in a DER file (binary certificate) and convert to a PEM string
        '''
        CERT__FILENAME = os.path.join(filename)
        f = open(CERT__FILENAME, "rb")
        try:
            der_cert = f.read()
        except:
            print("Error opening certificate file: ", filename)
        finally:
            f.close()

        return der_cert

    @staticmethod
    def verify_chain_of_trust(cert_pem, trusted_cert_pems):
        '''
        This method uses the pyOpenSSL module to verify the chain of X509 PEM encoded certificates
        NOTE: This requires a newer version of pyOpenSSL that does not come with CentOS/RHEL
        Need to install an updated version of pyOpenSSL using pip install pyopenssl
        Tested with version: pyopenssl-17.5.0
        '''
        certificate = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)

        # Create and fill a X509Sore with trusted certs
        store = crypto.X509Store()
        for trusted_cert_pem in trusted_cert_pems:
            trusted_cert = crypto.load_certificate(crypto.FILETYPE_PEM, trusted_cert_pem)
            store.add_cert(trusted_cert)

        # Create a X590StoreContext with the cert and trusted certs
        # and verify the the chain of trust
        store_ctx = crypto.X509StoreContext(store, certificate)
        # Returns None if certificate can be validated
        result = store_ctx.verify_certificate()

        if result is None:
            return True
        else:
            return False
