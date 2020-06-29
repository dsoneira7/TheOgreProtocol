from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Hash import HMAC
from Crypto import Random
from Crypto.Protocol.KDF import PBKDF2
from numpy import random
from termcolor import colored
import config
import struct
import socket
import signal
import os
import sys


def pad_message(message):
    """
    Pads a string for use with AES encryption
    :param message: string to be padded
    :return: padded message
    """
    print "message_length before padding: " + str(len(message))
    pad_size = 16 - (len(message) % 16)
    if pad_size == 0:
        pad_size = 16
    message += chr(pad_size) * pad_size
    print "message_length after padding: " + str(len(message))
    return message


def unpad_message(message):
    return message[:-ord(message[-1])]


def add_layer(message, aes_key):
    ciphertext = aes_encrypt(message, aes_key)
    return ciphertext


def peel_layer(ciphertext, aes_key):
    message = aes_decrypt(ciphertext, aes_key)
    return message

# uses the PUBLIC key in 'key' to encrypt


def wrap_message(message, rsa_key, aes_key):
    # generate AES key, 'k'
    # encrypt message (param 'message') with AES using 'k'
    # encrypt 'k' with RSA key (param 'key')
    # assemble final blob, then return it

    ciphertext_aes = aes_encrypt(message, aes_key)
    print "wrapping before rsa_encryption length " + str(len(aes_key)) + " value!: " + str(aes_key)
    cipher = PKCS1_OAEP.new(rsa_key.publickey())
    ciphertext_rsa = cipher.encrypt(aes_key)
    print "wrapping after rsa_encryption length " + str(len(ciphertext_rsa)) + " value!: " + str(ciphertext_rsa)
    blob = ciphertext_rsa + ciphertext_aes
    return blob


def unwrap_message(blob, rsa_key):
    # seperate blob into data and encrypted AES key
    # decrypt AES key using given RSA key
    # decrypt data using the AES key
    # return the unencrypted orignal blob

    ciphertext_rsa = blob[0:128]
    ciphertext_aes = blob[128:len(blob)]
    print str(len(blob))
    print(str(len(ciphertext_rsa)))
    cipher = PKCS1_OAEP.new(rsa_key)
    aes_key = cipher.decrypt(ciphertext_rsa)
    print str(len(aes_key))
    message = aes_decrypt(ciphertext_aes, aes_key)
    return message, aes_key

# assumes 'message' is no longer than 4096 bytes


def send_message_with_length_prefix(tosocket, message):
    prefix = struct.pack("!I", len(message))
    # 4 bytes, should send all of it in one go
    bytessent = sendn(tosocket, prefix)
    if bytessent == 0:
        return False
    bytessent = sendn(tosocket, message)
    if bytessent == 0:
        return False
    return True

# returns an empty string if the connection closed on the other end


def recv_message_with_length_prefix(fromsocket):
    packedlen = recvn(fromsocket, 4)
    if packedlen == "":
        return ""
    length = struct.unpack("!I", packedlen)[0]
    message = recvn(fromsocket, length)
    return message


# socket on the other end has closed if this returns 0
def sendn(tosocket, message):
    length = len(message)
    sent_so_far = 0
    while length > sent_so_far:
        bytessent = tosocket.send(message[sent_so_far:])
        if bytessent == 0:
            return 0
        sent_so_far += bytessent
    return length


def recvn(fromsocket, length):
    recv_so_far = 0
    recvbuf = ""
    while length > recv_so_far:
        newdata = fromsocket.recv(length - recv_so_far)
        bytesrecvd = len(newdata)
        if bytesrecvd == 0:
            return ""
        recvbuf += newdata
        recv_so_far += bytesrecvd
    return recvbuf


def packHostPort(ip, port):
    return socket.inet_aton(ip) + struct.pack("!i", port)


def unpackHostPort(packed):
    return (socket.inet_ntoa(packed[:4]), struct.unpack("!i", packed[4:])[0])

# hoplist is a list of tuples of the form (packedhop, RSA key object)


def packRoute(hoplist):
    message = ""
    for i in range(0, len(hoplist)):
        idx = len(hoplist) - 1 - i
        message = hoplist[idx][0] + message
        message = wrap_message(message, hoplist[idx][1])
    return message

# destination is a pre-packed hostport string




def wrap_all_messages(hoplist, message):

    randfile = Random.new()
    aes_key_list = []
    for i in range(0, len(hoplist)):
        aes_key_list.append(randfile.read(32))

    #We generate the padding random blocks to respect the global length of the extended onion
    random_blocks = generate_random_blocks(config.HOP_LIMIT - len(hoplist))
    dummy_paddings = generate_dummy_paddings(hoplist, aes_key_list)

    reversed_aes_key_list = list(reversed(aes_key_list))

    message_length = str(len(message))
    while len(message_length) != 3:
        message_length = "0" + message_length

    wrapped_message = "0"*8 + message_length + message
    ciphered_tags = []
    packedroute = ""
    for i in range(0, len(hoplist)):
        # have some way of getting each, probably from directory authority
        rsa_key = hoplist[i][2]

        tag = wrapped_message
        for ciphered_tag in list(reversed(ciphered_tags)):
            tag += ciphered_tag
        for random_block in random_blocks:
            tag += random_block
        count = 0
        for k in range(len(hoplist) - (i+2), -1, -1):
            print "k: " + str(k) + " count: " + str(count)
            print colored("padding added length: " + str(len(dummy_paddings[k][count])) + " value:" + str(dummy_paddings[k][count]), 'yellow')
            tag += dummy_paddings[k][count]
            count += 1

        print "tag length on iteration " + str(i) + ": " + str(len(tag)) + " value: " + str(tag)
        reconstruct = tag
        if i == 1:
            pointer = 0
            for a in range(0, 4):
                if a == 0:
                    actual = tag[:32]
                    pointer = 32
                else:
                    actual = tag[pointer:(pointer + 128)]
                    pointer += 128
                print "BLOQUE NUMERO " + str(a) + " VALUE: " + str(actual)
        if(i == 2):
            pointer=0
            for a in range (0,4):
                if a==0:
                    actual = tag[:176]
                    pointer = 176
                    reconstruct = actual
                else:
                    actual = tag[pointer:(pointer+128)]
                    pointer+=128
                    reconstruct += actual
                print "bloque numero " + str(a) + " value: " + str(actual)
            print "reconstruido length: " + str(len(reconstruct)) + " value: " + str(reconstruct)
        print "aes_key length: " + str(len(reversed_aes_key_list[i])) + " value: " + str(reversed_aes_key_list[i])
        hmac = HMAC.new(reversed_aes_key_list[i], reconstruct, SHA256)
        ciphered_tag = hmac.digest()
        print "ciphered_tag_length " + str(len(ciphered_tag)) + " value: " + str(ciphered_tag)
        ciphered_tags.append(rsa_key.encrypt(ciphered_tag, rsa_key.publickey())[0])
        print "ciphered_tag_length after encryption " + str(len(ciphered_tags[i])) + " value: " + str(ciphered_tags[i])
        for c in reversed_aes_key_list:
            print colored(str(c), 'red')
        if i != (len(hoplist)-1):
            print "ENCRYPTING WITH AES_KEY: " + str(reversed_aes_key_list[i + 1])
            for x in range(0, len(ciphered_tags)):
                ciphered_tags[x] = aes_encrypt(ciphered_tags[x], reversed_aes_key_list[i+1])
            for x in range(0, len(random_blocks)):
                random_blocks[x] = aes_encrypt(random_blocks[x], reversed_aes_key_list[i+1])
        cont = 0
        for b in hoplist:
            print colored(str(b) + ": " + str(b[0]) + ":" + str(b[1]), 'red')
            cont+=1
        if i!=0:
            packedroute = packHostPort(hoplist[i-1][0], hoplist[i-1][1])
        wrapped_message = packedroute + wrapped_message
        wrapped_message = wrap_message(
            pad_message(wrapped_message),
            rsa_key,
            reversed_aes_key_list[i]
        )
        print "wrappes_message_length iteracion " + str(i) + " " + str(len(wrapped_message))
    counter = 0
    for ciphered_tag in list(reversed(ciphered_tags)):
        wrapped_message += ciphered_tag
        counter+=1
        print ""
        print ""
        print ""
        print "this tag length: " + str(len(ciphered_tag)) + " value: " + str(ciphered_tag)
        print ""
        print ""
        print ""

    print "hemos anhadido estos tags" + str(counter)
    counter = 0
    for random_block in random_blocks:
        wrapped_message += random_block
        counter+=1
    print "hemos anhadido estos bloques aleatorios" + str(counter)
    print "wrappes_message_length finalizado par enviar " + str(len(wrapped_message))
    return wrapped_message, aes_key_list


def add_all_layers(aes_key_list, message):
    message = pad_message(message)
    for key in aes_key_list:
        message = add_layer(message, key)
    return message


def peel_all_layers(aes_key_list, response):
    for i in reversed(range(0, len(aes_key_list))):
        response = peel_layer(response, aes_key_list[i])
    response = unpad_message(response)
    return response


def process_route(data):
    print data
    hoplist = []
    for a in range(3):
        rsa_key = data[8:220]
        hostport = unpackHostPort(data[:8])
        hoplist.append((hostport[0], hostport[1], RSA.importKey(rsa_key)))
        data = data[220:]
    return hoplist


def signal_handler(received_signal, frame):
    os.killpg(os.getpgid(0), signal.SIGINT)
    sys.exit(0)


def generate_random_blocks(n_random_blocks):
    random_blocks = []
    for i in range(n_random_blocks):
        random_blocks[i] = random.bytes(32)
    return random_blocks


#TODO: COMENTAR PARA EXPLICAR CODIGO, OU FACELO UN POUCO MAIS COMPRENSIBLE.
def generate_dummy_paddings(hoplist, aes_key_list):
    reverse_hoplist = list(reversed(hoplist))
    #reverse_aes_key_list = list(reversed(aes_key_list))

    padding_map = [["" for x in range(len(reverse_hoplist) - 1)] for y in range(len(reverse_hoplist) - 1)]

    for i in range(0, len(reverse_hoplist) - 1):
        print "dummy_paddings i: "+ str(i)
        padding_map[0][i] = PBKDF2(
            aes_key_list[i],
            packHostPort(reverse_hoplist[i][0], reverse_hoplist[i][1]),
            128,
            config.KDF_ITERATIONS)
        print colored(
            "padding generated with aes_key("+str(len(aes_key_list[i]))+"): " + str(aes_key_list[i]) + " and hostport: " + str(reverse_hoplist[i][0]) + ":" + str(reverse_hoplist[i][1]) + " length: " + str(
                len(padding_map[0][i])) + " value:" + str(padding_map[0][i]), 'blue')

        k = i
        for j in range(0, i):
            print "dummy_paddings k: " + str(k)
            print "dummy_paddings j: " + str(j)
            padding_map[k][j] = aes_decrypt(padding_map[k-1][j], aes_key_list[j])
            k -= 1

    return padding_map


def verify(aes_key, to_be_verified, signature, rsa_key):
    hmac = HMAC.new(aes_key, to_be_verified, SHA256)
    digest = hmac.digest()
    encrypted_digest = rsa_key.encrypt(digest, rsa_key.publickey())[0]
    print "encrypted_digest_length: " + str(len(encrypted_digest)) + " encrypted_digest: " + str(encrypted_digest)
    decrypted_digest = rsa_key.decrypt(digest)
    print "decrypted_digest_length: " + str(len(decrypted_digest)) + " decrypted_digest: " + str(decrypted_digest)
    print "aes_key length: " + str(len(aes_key)) + " value: " + str(aes_key)
    print "digest_length: " + str(len(digest)) + " digest: " + str(digest)
    print "signature_length: " + str(len(signature)) + " signature: " + str(signature)
    return digest == signature


def add_new_padding(onion, old_padding, hostport, aes_key):
    dummy_padding = PBKDF2(
            aes_key,
            hostport,
            128,
            config.KDF_ITERATIONS)

    print colored("padding generated with aes_key("+str(len(aes_key))+"): " + str(aes_key) + " and hostport: " + str(unpackHostPort(hostport)[0]) + ":" + str(unpackHostPort(hostport)[1]) + " length: " + str(len(dummy_padding)) + " value:" + str(dummy_padding),'magenta')

    new_padding = ""
    for i in range(1, config.HOP_LIMIT):
        new_padding += aes_decrypt(old_padding[i*128:(i+1)*128], aes_key)
    new_padding += dummy_padding
    return onion + new_padding


def aes_encrypt(data, aes_key):
    aes_obj = AES.new(aes_key, AES.MODE_CBC, "0" * 16)
    return aes_obj.encrypt(data)


def aes_decrypt(data, aes_key):
    aes_obj = AES.new(aes_key, AES.MODE_CBC, "0" * 16)
    return aes_obj.decrypt(data)
