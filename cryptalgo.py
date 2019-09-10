import hashlib
import base64
import binascii
import os
from random import randint,choice
import getpass
import pyperclip

class Cryptoshiz(object):
	def __init__(self):
		pass

	def set_encryption_file(self):
		try:
			encrypt_this_file = raw_input('Input file path to encrypt\n')
		except:
			encrypt_this_file = input('Input file path to encrypt\n')   
	#read file to string
		with open(encrypt_this_file, 'r') as plain_text_file:
			self.plaintext_string = plain_text_file.read()
		try:
			self.base_64_encoded_message = base64.b64encode(bytes(self.plaintext_string))
		except:
			self.base_64_encoded_message = base64.b64encode(bytes(self.plaintext_string,'utf-8'))
	def set_encrypted_message(self):
		try:
			message_to_encode = raw_input('Input Message to encrypt\n')
		except:
			message_to_encode = input('Input Message to encrypt\n')
		try:
			self.base_64_encoded_message = base64.b64encode(bytes(message_to_encode))
		except:
			self.base_64_encoded_message = base64.b64encode(bytes(message_to_encode,'utf-8'))

		print(self.base_64_encoded_message)

	def set_encryption_key(self):
		selection = ''
		while selection != 'next':
			try:
				selection = raw_input('[1]Use File to Encrypt\n[2]Use Text to Encrypt\nEnter Selction: ')
			except:
				selection = input('[1]Use File to Encrypt\n[2]Use Text to Encrypt\nEnter Selction: ')

			if str(selection) == '1':
				try:
					encrypt_with_file = raw_input('Input file path to be used as key\n')
				except:
					encrypt_with_file = input('Input file path to be used as key\n')

				with open(encrypt_with_file,'rb') as key_file:
					self.encryption_key = base64.b64encode(bytes(ifile.read())).decode('utf-8').replace('=','')
				selection = 'next'
			if str(selection) == '2':
				try:
					encrypt_with_string = raw_input('Enter string to be used as key\n')
				except:
					encrypt_with_string = input('Enter string to be used as key\n')

				self.encryption_key = (base64.b64encode(bytes(encrypt_with_string)).decode('utf-8')).replace('=','')
				selection = 'next'

	def do_encryption(self):

		self.rand_encrypt_string = ''


		bin_list = []
        
		for bchar in self.base_64_encoded_message:
			try:
				bin_list.append(format(ord(bchar), '09b'))
			except:
				bin_list.append("{0:09b}".format(bchar))

		self.bin_string = ''.join(bin_list)

		i = 0
		for bin in self.bin_string:
			if bin == '0':
				rand_picker = randint(0,2)
				random_number = (randint(48,57),randint(65,90),randint(97,122))[rand_picker]
				rand_char = chr(random_number)
				if rand_char != self.encryption_key[i%len(self.encryption_key)]:
					self.rand_encrypt_string += rand_char
				else:
					random_number2 = (randint(48,57),randint(65,90),randint(97,122))[(rand_picker+1)%3]
					rand2_char = chr(random_number2)
					self.rand_encrypt_string += rand2_char

			if bin == '1':
				self.rand_encrypt_string += self.encryption_key[i%len(self.encryption_key)]

			i += 1

		self.base64_rand_encrypt_string = base64.b64encode(bytes(self.rand_encrypt_string))
        
		try:
			cipher_path = raw_input('Input File Path to send Ciphertext file\n')
		except:
			cipher_path = input('Input File Path to send Ciphertext file\n')
		 
		success = ''
		while success != '1':
			try:
				with open(cipher_path,'w') as cipher_file:
					cipher_file.write(self.base64_rand_encrypt_string.decode('utf-8'))
				try:    
					print_cipher = raw_input('Show Cipher?(y/n)\n')
				except:
					print_cipher = input('Show Cipher?(y/n)\n')
		    
				success = '1'
			except Exception as e:
				print(e)
		if print_cipher == 'y':
			print(self.base64_rand_encrypt_string.decode('utf-8'))
	def input_key(self):
        # open Cipher File
		try:
			open_cipher_file = raw_input('Input File to be Decrypted\n')
		except:
			open_cipher_file = input('Input File to be Decrypted\n')

		with open(open_cipher_file,'r') as cipher_file:
			self.cipher_string = cipher_file.read()

		self.ciphered_decoded_base64 = base64.b64decode(self.cipher_string)
		#open Key File
		selection = ''
		while selection != 'next':
			try:
				selection = raw_input('[1]Use File to Decrypt\n[2]Use Text to decrypt\n')
			except:
				selection = input('[1]Use File to Decrypt\n[2]Use Text to decrypt\n')
		

			if selection == '1':
				try:
					key_file_input = raw_input('Input Key File\n')
				except:
					key_file_input = input('Input Key File\n')
				with open(key_file_input,'rb') as key_file:
					self.key_string = base64.b64encode(key_file.read()).decode('utf-8').replace('=','')
				selection = 'next'

			if selection == '2':
				try:
					self.key_string = base64.b64encode(bytes(getpass.getpass('Input Key Text\n'))).decode('utf-8').replace('=','')
				except:
					self.key_string = base64.b64encode(bytes(getpass.getpass('Input Key Text\n'),'utf-8')).decode('utf-8').replace('=','')

				selection = 'next'

	def set_key_string(self):
		try:
			self.key_string = base64.b64encode(bytes(self.key_phrase)).decode('utf-8').replace('=','')
		except:
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
                pyperclip.copy(self.decoded_string2)
		#print(self.decoded_string2)
		write2file = raw_input('Write to file?(y/n)')
		if write2file == 'y':
			input_decrypted_file = raw_input('Input name for decrypted file\n')
			with open(input_decrypted_file,'w') as decrypted_file:
				decrypted_file.write(self.decoded_string2)

if __name__ == '__main__':
	crypted = Cryptoshiz()
	encrypt_or_decrypt = ''
	while encrypt_or_decrypt != 'next':
		try:
			encrypt_or_decrypt = raw_input('[1]Encrypt\n[2]Decrypt\n')
		except:
			encrypt_or_decrypt = input('[1]Encrypt\n[2]Decrypt\n')

		if encrypt_or_decrypt == '1':
			selection = ''
			while selection !='next':
				try:
					selection = raw_input('[1]Encrypt File\n[2]Encrypt Text\n')
				except:
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
