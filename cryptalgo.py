import hashlib
import base64
import binascii
from random import randint


class Cryptoshiz(object):
    def __init__(self):
        pass

    def set_encryption_file(self):

        encrypt_this_file = input('Input file path to encrypt\n')
        #read file to string
        with open(encrypt_this_file, 'r') as plain_text_file:
            self.plaintext_string = plain_text_file.read()
        self.base_64_encoded_message = base64.b64encode(bytes(self.plaintext_string,'utf-8'))

    def set_encrypted_message(self):

        message_to_encode = input('Input Message to encrypt\n')
        self.base_64_encoded_message = base64.b64encode(bytes(message_to_encode,'utf-8'))
        print(self.base_64_encoded_message)

    def set_encryption_key(self):
        selection = ''
        while selection != 'next':
            selection = input('[1]Use File to Encrypt\n[2]Use Text to Encrypt\nEnter Selction: ')
            if str(selection) == '1':

                encrypt_with_file = input('Input file path to be used as key\n')

                with open(encrypt_with_file,'rb') as key_file:
                    self.encryption_key = base64.b64encode(bytes(ifile.read())).decode('utf-8').replace('=','')
                selection = 'next'
            if str(selection) == '2':
                encrypt_with_string = input('Enter string to be used as key\n')
                self.encryption_key = (base64.b64encode(bytes(encrypt_with_string,'utf-8')).decode('utf-8')).replace('=','')
                selection = 'next'

    def do_encryption(self):

        self.rand_encrypt_string = ''


        bin_list = []
        for bchar in self.base_64_encoded_message:
            bin_list.append("{0:09b}".format(bchar))
        self.bin_string = ''.join(bin_list)

        i = 0
        for bin in self.bin_string:
            if bin == '0':
                random_number = randint(32,126)
                rand_char = chr(random_number)
                if rand_char != self.encryption_key[i%len(self.encryption_key)]:
                    self.rand_encrypt_string += rand_char
                else:
                    rand2_char = chr(((ord(rand_char)+1)%126+31))
                    self.rand_encrypt_string += rand2_char

            if bin == '1':
                self.rand_encrypt_string += self.encryption_key[i%len(self.encryption_key)]

            i += 1

        self.base64_rand_encrypt_string = base64.b64encode(bytes(self.rand_encrypt_string,'utf-8'))
        cipher_path = input('Input File Path to send Ciphertext file\n')
        success = ''
        while success != '1':
            try:
                with open(cipher_path,'w') as cipher_file:
                    cipher_file.write(self.base64_rand_encrypt_string.decode('utf-8'))
                print_cipher = input('Show Cipher?(y/n)\n')
                success = '1'
            except Exception as e:
                print(e)
        if print_cipher == 'y':
            print(self.base64_rand_encrypt_string.decode('utf-8'))
    def input_key(self):
        # open Cipher File
        open_cipher_file = input('Input File to be Decrypted\n')
        with open(open_cipher_file,'r') as cipher_file:
            self.cipher_string = cipher_file.read()

        self.ciphered_decoded_base64 = base64.b64decode(self.cipher_string)
        #open Key File
        selection = ''
        while selection != 'next':
            selection = input('[1]Use File to Decrypt\n[2]Use Text to decrypt\n')

            if selection == '1':
                key_file_input = input('Input Key File\n')
                with open(key_file_input,'rb') as key_file:
                    self.key_string = base64.b64encode(key_file.read()).decode('utf-8').replace('=','')
                selection = 'next'

            if selection == '2':
                self.key_string = base64.b64encode(bytes(input('Input Key Text\n'),'utf-8')).decode('utf-8').replace('=','')
                selection = 'next'

    def set_key_string(self):
        self.key_string = base64.b64encode(bytes(self.key_phrase,'utf-8')).decode('utf-8').replace('=','')

    def do_decryption(self):
        self.ciphered_decoded_base64 = base64.b64decode(self.cipher_string)
        bin_decoded = ''

        n = 0
        for c in self.ciphered_decoded_base64.decode('utf-8'):
            if c == self.key_string[n%len(self.key_string)]:
                bin_decoded += '1'
            else:
                bin_decoded += '0'
            n+=1

        self.bin_decoded_array = [bin_decoded[i:i+9] for i in range(0, len(bin_decoded),9)]

        dec_decoded_array = []
        for line in self.bin_decoded_array:
            dec_decoded_array.append(int(line,2))

        decoded_string = ''
        for line in dec_decoded_array:
            decoded_string += chr(line)

        self.decoded_string2 = base64.b64decode(decoded_string).decode('utf-8')

    def print_decoded(self):
        print(decoded_string)
        print(self.decoded_string2)
        input_decrypted_file = input('Input name for decrypted file\n')
        with open(input_decrypted_file,'w') as decrypted_file:
            decrypted_file.write(self.decoded_string2)

if __name__ == '__main__':
    crypted = Cryptoshiz()
    encrypt_or_decrypt = ''
    while encrypt_or_decrypt != 'next':
        encrypt_or_decrypt = input('[1]Encrypt\n[2]Decrypt\n')
        if encrypt_or_decrypt == '1':
            selection = ''
            while selection !='next':
                selection = input('[1]Encrypt File\n[2]Encrypt Text\n')
                if selection == '1':
                    crypted.set_encryption_file()
                    selection = 'next'

                if selection == '2':
                    crypted.set_encrypted_message()
                    selection = 'next'

            crypted.set_encryption_key()
            crypted.do_encryption()
            encrypt_or_decrypt = 'next'
        if encrypt_or_decrypt == '2':
            crypted.input_key()
            crypted.do_decryption()
            crypted.print_decoded()
