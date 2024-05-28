from Crypto.Cipher import AES
from Crypto import Random
import hashlib
import getpass
import base64
import shutil
import sys
import os


class encryptor:
    def __init__(self, password:bytearray, path:str) -> None:
        self.block_size = AES.block_size
        self.count = 0
        self.key = hashlib.sha256(password).digest()
        self.path = path
        self.backup_path = "{}-backup".format(path)

        # Backup directory
        print('\n Making a backup...')
        if os.path.exists(self.backup_path): shutil.rmtree(self.backup_path)
        shutil.copytree(path, self.backup_path)
        print(' ✓ Made a backup.\n')

        try:
            # Iterate thought files and directories in the path.
            for file in os.listdir(path):
                # Schedule files/directories to encrypt
                self.schedule(path + '/' + file)
            print('\n ✓ Encrypted {} files'.format(self.count))
        except:
            print(' x Something went wrong.')
        else:
            # Remove the backup after finishing
            print('\n Removing the backup...')
            # shutil.rmtree("{}-backup".format(path))
            print(' ✓ Removed the backup.\n')

            # Rename Directory
            os.rename(path, "{}.enc".format(path))

    def pad(self, s:bytearray) -> bytearray:
        # Padding is a way to take data that may or may not be a multiple of the block size
        # for a cipher and extend it out so that it is.
        gt = (self.block_size - len(s) % self.block_size) * chr(self.block_size - len(s) % self.block_size)
        return s + gt.encode('utf8')
    
    def encrypt_name(self, name:str) -> str:
        # Return new name
        return base64.b85encode(name.encode('utf8')).decode('utf8')

    # Encrypt function
    def encrypt_content(self, raw:bytearray) -> bytearray:
        # Generate an initial vector
        iv = Random.new().read(self.block_size)
        
        # Pad
        raw = self.pad(raw)

        # Encrypt
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(raw)
        
        # return
        return iv + ciphertext
    
    def encrypt_file(self, full_path:str) -> None:
        # Open file for reading as binary
        with open(full_path, 'rb') as f:
            # Encrypt
            ciphertext = self.encrypt_content(f.read())

        # Open file for writing as binary
        with open(full_path, 'wb') as f:
            f.write(ciphertext)

    def schedule(self, full_path:str) -> None:
        name = os.path.basename(full_path)
        dir_path = os.path.dirname(full_path)
        new_name = self.encrypt_name(name)

        # If the file is a directory
        if os.path.isdir(full_path):
            # Iterate through files
            for subName in os.listdir(full_path):
                self.schedule(full_path + '/' + subName)
        else:
            print(" + [{}]\t Encrypting '{}'".format(self.count, new_name))
            self.encrypt_file(full_path)
            self.count += 1
        
        # Rename the file/directory
        os.rename(full_path, "{}/{}".format(dir_path, new_name))

if __name__ == "__main__":
    # Get dir path
    try:
       path = sys.argv[1]
       print('')
    except IndexError:
       while True:
           path = input('\n > Enter files directory: ')

           if os.path.isdir(path):
               break
           else:
               print(' \n Directory does not exist.')
    
    # Get secret
    while True:
       key = getpass.getpass(' > Enter a secret key\t: ').encode('utf8')
       repeat = getpass.getpass(' > Repeat the key\t: ').encode('utf8')

       if key == repeat:
           encryptor = encryptor(key, path)
           break
       else:
           print('\n Keys did not match. Try again.\n')
