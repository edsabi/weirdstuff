import hashlib
import base64
import binascii
from random import randint
#encrypt to base64
file = open('cat_memes.txt', 'r')
crypted = base64.b64encode(bytes(file.read(),'utf-8'))
file.close()
num_list=[]
for line in crypted:
    num_list.append(line)
bin_array=[]
for line in num_list:
    bin_array.append("{0:09b}".format(line))
bin_string = "".join(bin_array)
encoded_stuff=''
rand_int=''
decoded_string=''
i=0

with open('Keyfile','rb') as dank_memes:

    fun_string = base64.b64encode(bytes(dank_memes.read()))
key_string = fun_string.decode('utf-8')
for chars in bin_string:
    if chars == '0':

        rand_char = chr(randint(32,126))
        if rand_char != key_string[i%len(key_string)]:
            encoded_stuff += rand_char
        else:
            rand2_char = chr(((ord(rand_char)+1)%126+31))
            encoded_stuff += rand2_char

    if chars == '1':
        encoded_stuff += key_string[i%len(key_string)]
    i+=1
encoded_stuff2 = base64.b64encode(bytes(encoded_stuff,'utf-8'))
with open('HAX.txt', 'w') as sweet_file:
    sweet_file.write(encoded_stuff2.decode('utf-8'))
with open('meow.txt','w') as meow_file:
    meow_file.write(hashlib.sha256(encoded_stuff2).hexdigest())
#DECODE!!
n=0


bin_decoded=''

for c in encoded_stuff:
    if c == key_string[n%len(key_string)]:
        bin_decoded += '1'

    else:
        bin_decoded +='0'
    n+=1

bin_decoded_array = [bin_decoded[i:i+9] for i in range(0, len(bin_decoded),9)]
dec_decoded_array=[]
for line in bin_decoded_array:
    dec_decoded_array.append(int(line,2))
for line in dec_decoded_array:
    decoded_string += chr(line)
decoded_string2 = base64.b64decode(decoded_string)
