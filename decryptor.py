from Crypto.Cipher import AES
import hashlib
import getpass
import base64
import sys
import os


class decryptor:
    def __init__(self, key:bytearray, path:str) -> None:
        self.block_size = AES.block_size
        self.key = hashlib.sha256(key).digest()
        self.path = path
        self.count = 0
        
        if path.endswith('.enc'):
            # Iterate through files/directories
            for file in os.listdir(path):
                self.schedule(path + '/' + file)
            
            # Rename Directory
            os.rename(path, path[:-4])
        else:
            print(' The directory is not an encryption folder')
    
    def unpad(self, s:bytearray):
        return s[:-ord(s[len(s)-1:])]

    # Encrypt function
    def decrypt_content(self, ciphertext:bytearray) -> bytearray:
        # Get the initial vector
        iv = ciphertext[:self.block_size]

        # Decrypt
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        text = cipher.decrypt(ciphertext[self.block_size:])
        
        # Unpad text
        text = self.unpad(text)

        # return
        return text
    
    def decrypt_file(self, full_path):
        # Decrypt file content
        with open(full_path, 'rb') as f:
            content = self.decrypt_content(f.read())
        
        # Overwrite binary with decrypted content
        with open(full_path, 'wb') as f:
            f.write(content)

    def schedule(self, full_path):
        name = os.path.basename(full_path)
        dir_path = os.path.dirname(full_path)
        new_name = base64.b85decode(name.encode('utf8')).decode('utf8')
        new_full_path = dir_path + '/' + new_name

        # Rename
        os.rename(full_path, new_full_path)
        
        # If was a directory
        if os.path.isdir(new_full_path):
            # Iterate through files/directories
            for subName in os.listdir(new_full_path):
                self.schedule(new_full_path + '/' + subName)
        else:
            print(" + [{}]\tDecrypting '{}'".format(self.count, name[:35] + '...' if 35 < len(name) else name))
            self.decrypt_file(new_full_path)
            self.count += 1

if __name__ == "__main__":
    # Get dir path
    try:
       path = sys.argv[1]
       print('')
    except IndexError:
       path = input('\n > Enter files directory: ')
    
    # Get secret
    key = getpass.getpass(' > Enter the secret key:\t').encode('utf8')
    print('')
    decryptor = decryptor(key, path)
    print('\n > Decrypted {} files.\n'.format(decryptor.count))
