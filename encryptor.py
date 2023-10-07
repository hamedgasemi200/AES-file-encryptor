from Crypto.Cipher import AES
from Crypto import Random
import hashlib
import getpass
import base64
import sys
import os


class encryptor:
    def __init__(self, key:bytearray, path:str) -> None:
        self.block_size = AES.block_size
        self.key = hashlib.sha256(key).digest()
        self.path = path
        self.count = 0
        
        for file in os.listdir(path):
            self.schedule(path + '/' + file)

    def pad(self, s:bytearray) -> bytearray:
        # Padding is a way to take data that may or may not be a multiple of the block size
        # for a cipher and extend it out so that it is.
        gt = (self.block_size - len(s) % self.block_size) * chr(self.block_size - len(s) % self.block_size)
        return s + gt.encode('utf8')
    
    # Encrypt function
    def encrypt(self, raw:bytearray) -> bytearray:
        # Generate an initial vector
        iv = Random.new().read(self.block_size)
        
        # Pad
        raw = self.pad(raw)

        # Encrypt
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(raw)
        
        # return
        return iv + ciphertext

    def schedule(self, full_path:str) -> None:
        name = os.path.basename(full_path)
        dir_path = os.path.dirname(full_path)
        new_name = base64.b85encode(name.encode('utf8')).decode('utf8')
        new_full_path = dir_path + '/' + new_name

        # If is a valid base85
        try:
            base64.b85decode(name)
            print(" + '{}'\t-\t already encrypted.".format(name[:35] + '...' if 35 < len(name) else name))
            return None
        except Exception as e:
            self.count += 1
            print(" + [{}]\tEncrypting '{}'".format(self.count, name))

        # Rename
        os.rename(full_path, new_full_path)

        # If was a directory
        if os.path.isdir(new_full_path):
            # Iterate through files
            for subName in os.listdir(new_full_path):
                self.schedule(new_full_path + '/' + subName)
        else:
            pass
            # Open file for reading as binary
            with open(new_full_path, 'rb') as f:
                # Encrypt
                ciphertext = self.encrypt(f.read())
            
            # Open file for writing as binary
            with open(new_full_path, 'wb') as f:
                f.write(ciphertext)

if __name__ == "__main__":
    # Get dir path
    try:
       path = sys.argv[1]
       print('')
    except IndexError:
       path = input('\n > Enter files directory: ')
    
    # Get secret
    while True:
       key = getpass.getpass(' > Enter a secret key: ').encode('utf8')
       repeat = getpass.getpass(' > Repeat the key\t: ').encode('utf8')

       if key == repeat:
           # Start encryption
           print('')
           encryptor = encryptor(key, path)
           print('\n # Eecrypted {} files.\n'.format(encryptor.count))
           break
       else:
           print('\n Keys did not match. Try again.')
