import argparse
import hashlib
import base64
import os
from Crypto.Cipher import AES


class decryptor:
    def __init__(self, key:bytearray, path:str) -> None:
        self.block_size = AES.block_size
        self.key = hashlib.sha256(key).digest()
        self.path = path
        self.count = 0
        
        # If path ends with .env
        if path.endswith('.enc'):
            # Iterate through files/directories
            for file in os.listdir(path):
                # Schedule item to decrypt
                self.schedule(path + '/' + file)
            
            # Remove '.enc' suffix
            os.rename(path, path[:-4])
        else:
            print(' The directory is not an encryption folder')
    
    def unpad(self, s:bytearray):
        return s[:-ord(s[len(s)-1:])]

    # Encrypt function
    def decrypt_name(self, name:str) -> str:
        # Return new name
        return base64.b85decode(name.encode('utf8')).decode('utf8')

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
    
    def decrypt_file(self, full_path:str) -> None:
        if os.stat(full_path).st_size == 0:
            return None

        # Decrypt file content
        with open(full_path, 'rb') as f:
            # Get content
            content = self.decrypt_content(f.read())
        
        # Overwrite binary with decrypted content
        with open(full_path, 'wb') as f:
            f.write(content)

    def schedule(self, full_path):
        name = os.path.basename(full_path)
        dir_path = os.path.dirname(full_path)
        new_name = self.decrypt_name(name)
        new_full_path = dir_path + '/' + new_name

        # If was a directory
        if os.path.isdir(full_path):
            # Iterate through files/directories
            for subName in os.listdir(full_path):
                # Schedule sub-files
                self.schedule('{}/{}'.format(full_path, subName))
        else:
            print(" + [{}]\t Decrypting '{}'".format(self.count, new_name[:35] + '...' if 35 < len(new_name) else new_name))
            self.decrypt_file(full_path)
            self.count += 1

        # Rename
        os.rename(full_path, new_full_path)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='decryptor', description='Decrypt your encrypted files.')
    parser.add_argument('password', type=str, help='Your chosen password to decrypt files.')
    parser.add_argument('directory', type=str, help='Encrypted files directory.')
    args = parser.parse_args()

    decryptor = decryptor(args.password.encode('utf8'), args.directory)
    print('\n\t > Decrypted {} files. \n'.format(decryptor.count))
