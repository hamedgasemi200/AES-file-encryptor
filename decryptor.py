from Crypto.Cipher import AES
import hashlib
import string
import os

class decryptor:
    def __init__(self, key:bytearray, path:str) -> None:
        self.block_size = AES.block_size
        self.key = hashlib.sha256(key).digest()
        self.path = path
        self.count = 0
        
        for file in os.listdir(path):
            self.schedule(path + '/' + file)
    
    def unpad(self, s:bytearray):
        return s[:-ord(s[len(s)-1:])]

    # Encrypt function
    def decrypt(self, ciphertext:bytearray) -> bytearray:
        # Get the initial vector
        iv = ciphertext[:self.block_size]

        # Decrypt
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        text = cipher.decrypt(ciphertext[self.block_size:])
        
        # Unpad text
        text = self.unpad(text)

        # return
        return text

    def schedule(self, full_path):
        name = os.path.basename(full_path)
        dir_path = os.path.dirname(full_path)

        if all(c not in string.hexdigits for c in name) or not name.endswith('.cr'):
            print(' --> The file is not an encrypted one.')
            return None

        new_name = bytes.fromhex(name[:-len('.cr')]).decode('utf8')
        new_full_path = dir_path + '/' + new_name
        
        self.count += 1
        print(" + [{}]\tDecrypting '{}'".format(self.count, name))

        # Rename
        os.rename(full_path, new_full_path)
        
        # If was a directory
        if os.path.isdir(new_full_path):
            # Iterate through files
            for subName in os.listdir(new_full_path):
                self.schedule(new_full_path + '/' + subName)
        else:
            # Overwrite binary with decrypted content
            with open(new_full_path, 'rb') as f: content = self.decrypt(f.read())
            with open(new_full_path, 'wb') as f: f.write(content)

if __name__ == "__main__":
   key = input(' > Enter a secret key:\t').encode('utf8')
   path = input(' > Enter files directory: ')
   print('')
   decryptor = decryptor(key, path)
   print('\n > Decrypted {} files.\n'.format(decryptor.count))