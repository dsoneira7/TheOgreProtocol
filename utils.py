from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Hash import HMAC
from Crypto import Random
from Crypto.Protocol.KDF import PBKDF2
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
    pad_size = 16 - (len(message) % 16)
    if pad_size == 0:
        pad_size = 16
    message += chr(pad_size) * pad_size
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

    ciphertext_aes = aes_encrypt(message[:config.IDENTIFIER_LENGTH], aes_key)
    pointer = 0
    while (config.IDENTIFIER_LENGTH + (pointer*config.ONION_BLOCK_LENGTH)) != len(message):
        start = config.IDENTIFIER_LENGTH + (pointer*config.ONION_BLOCK_LENGTH)
        end = start + config.ONION_BLOCK_LENGTH
        ciphertext_aes += aes_encrypt(message[start:end], aes_key)
        pointer += 1

    cipher = PKCS1_OAEP.new(rsa_key.publickey())
    ciphertext_rsa = cipher.encrypt(aes_key)
    blob = ciphertext_rsa + ciphertext_aes
    return blob


def unwrap_message(blob, rsa_key):
    # seperate blob into data and encrypted AES key
    # decrypt AES key using given RSA key
    # decrypt data using the AES key
    # return the unencrypted orignal blob

    print "ARRIVED ONION LENGTH " + str(len(blob))
    ciphertext_rsa = blob[0:128]
    ciphertext_aes = blob[128:len(blob)]
    cipher = PKCS1_OAEP.new(rsa_key)
    aes_key = cipher.decrypt(ciphertext_rsa)
    message = aes_decrypt(ciphertext_aes[:config.IDENTIFIER_LENGTH], aes_key)
    pointer = 0
    while (config.IDENTIFIER_LENGTH + (pointer * config.ONION_BLOCK_LENGTH)) != len(ciphertext_aes):
        start = config.IDENTIFIER_LENGTH + (pointer * config.ONION_BLOCK_LENGTH)
        end = start + config.ONION_BLOCK_LENGTH
        message += aes_decrypt(ciphertext_aes[start:end], aes_key)
        pointer += 1
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
    return socket.inet_ntoa(packed[:4]), struct.unpack("!i", packed[4:])[0]

# hoplist is a list of tuples of the form (packedhop, RSA key object)


def packRoute(hoplist):
    message = ""
    for i in range(0, len(hoplist)):
        idx = len(hoplist) - 1 - i
        message = hoplist[idx][0] + message
        message = wrap_message(message, hoplist[idx][1])
    return message

# destination is a pre-packed hostport string


def fixed_length_pad_message(wrapped_message):
    randfile = Random.new()
    pad_size = config.DATA_BLOCK_LENGTH - (len(wrapped_message) % config.DATA_BLOCK_LENGTH)
    if pad_size == 0:
        pad_size = config.DATA_BLOCK_LENGTH
    wrapped_message += randfile.read(pad_size)
    return wrapped_message


def wrap_all_messages(hoplist, message):
    print colored("Starting the onion creation process...", 'yellow')

    randfile = Random.new()
    aes_key_list = []
    print colored("Generating the secret asymmetrical keys for each node: ", 'yellow')
    for i in range(0, len(hoplist)):
        aes_key_list.append(randfile.read(32))
        print colored("k" + str(i+1) + ": " + str(aes_key_list[i]), 'yellow')

    # We generate the padding random blocks to respect the global length of the extended onion
    random_blocks = generate_random_blocks(config.HOP_LIMIT - len(hoplist))

    print colored("Generating pseudorandom padding blocks for the onions: ", 'yellow')
    onion_paddings = generate_paddings(hoplist, aes_key_list, 144)

    print colored("Generating pseudorandom padding blocks to add to the extension: ", 'yellow')
    dummy_paddings = generate_paddings(hoplist, aes_key_list, 128)

    reversed_aes_key_list = list(reversed(aes_key_list))

    message_length = str(len(message))

    message_length = ("0"*(3-len(message_length))) + message_length

    wrapped_message = message_length + message
    wrapped_message = fixed_length_pad_message(wrapped_message)
    ciphered_tags = []
    packedroute = "0"*8
    for i in range(0, len(hoplist)):
        rsa_key = hoplist[i][2]

        tag = wrapped_message
        for ciphered_tag in list(reversed(ciphered_tags)):
            tag += ciphered_tag
        for random_block in random_blocks:
            tag += str(random_block)
        count = 0
        for k in range(len(hoplist) - (i+2), -1, -1):
            tag += dummy_paddings[k][count]
            count += 1

        hmac = HMAC.new(reversed_aes_key_list[i], tag, SHA256)
        ciphered_tag = hmac.digest()
        ciphered_tags.append(rsa_key.encrypt(ciphered_tag, rsa_key.publickey())[0])
        print colored("Generated integrity block for P" + str(len(hoplist) - i) + ": " + str(ciphered_tags[i-1]),
                      'yellow')

        if i != (len(hoplist) - 1):
            for x in range(0, len(ciphered_tags)):
                ciphered_tags[x] = aes_encrypt(ciphered_tags[x], reversed_aes_key_list[i+1])
            for x in range(0, len(random_blocks)):
                random_blocks[x] = aes_encrypt(random_blocks[x], reversed_aes_key_list[i+1])

        print colored("Adding encryption layer number " + str(i+1) + " for P" + str(len(hoplist)-i) + ".", 'yellow')

        if i != 0:
            packedroute = packHostPort(hoplist[i-1][0], hoplist[i-1][1])
        packedroute = pad_message(packedroute)
        wrapped_message = packedroute + wrapped_message
        wrapped_message = wrap_message(
            wrapped_message,
            rsa_key,
            reversed_aes_key_list[i]
        )

        if i == 0:
            count = len(onion_paddings[0]) - 1
            for k in range(0, config.HOP_LIMIT - len(hoplist)):
                wrapped_message += randfile.read(config.ONION_BLOCK_LENGTH)
            for k in range(0, len(onion_paddings[0])):
                wrapped_message += onion_paddings[count][k]
                count -= 1
        else:
            wrapped_message = wrapped_message[:(len(wrapped_message) - config.ONION_BLOCK_LENGTH)]

    print colored("Resulting onion: " + str(wrapped_message), 'yellow')

    counter = 0
    for ciphered_tag in list(reversed(ciphered_tags)):
        wrapped_message += ciphered_tag
        counter += 1

    counter = 0
    for random_block in random_blocks:
        wrapped_message += random_block
        counter += 1

    print colored("Resulting extension: "
                  + str(wrapped_message[(config.DATA_BLOCK_LENGTH + (len(hoplist) * config.ONION_BLOCK_LENGTH)):]),
                  'yellow')

    print colored("Finished the onion creation process.", 'yellow')

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
    hoplist = []
    for a in range(3):
        rsa_key = data[8:220]
        hostport = unpackHostPort(data[:8])
        hoplist.append((hostport[0], hostport[1], RSA.importKey(rsa_key)))
        data = data[220:]
    return hoplist


def signal_handler():
    os.killpg(os.getpgid(0), signal.SIGINT)
    sys.exit(0)


def generate_random_blocks(n_random_blocks):
    randfile = Random.new()
    print colored("Generating " + str(n_random_blocks) + " random blocks.", 'yellow')
    random_blocks = []
    for i in range(n_random_blocks):
        random_blocks.append(randfile.read(128))
        print colored("Generated block number " + str(i+1) + ": " + str(random_blocks[i]), 'yellow')
    return random_blocks


def generate_paddings(hoplist, aes_key_list, block_size):
    reverse_hoplist = list(reversed(hoplist))

    padding_map = [["" for x in range(len(reverse_hoplist) - 1)] for y in range(len(reverse_hoplist) - 1)]

    for i in range(0, len(reverse_hoplist) - 1):
        padding_map[0][i] = PBKDF2(
            aes_key_list[i],
            packHostPort(reverse_hoplist[i][0], reverse_hoplist[i][1]),
            block_size,
            config.KDF_ITERATIONS)
        print colored(
            "padding generated with k" + str(i+1) + " and identifier: " + str(reverse_hoplist[i][0]) + ":"
            + str(reverse_hoplist[i][1]) + ": " + str(padding_map[0][i]), 'yellow')

        k = i
        for j in range(0, i):
            padding_map[k][j] = aes_decrypt(padding_map[k - 1][j], aes_key_list[i])
            k -= 1

    return padding_map


def verify(aes_key, to_be_verified, signature):
    hmac = HMAC.new(aes_key, to_be_verified, SHA256)
    digest = hmac.digest()
    print colored("hashed onion || N-1 blocks: " + str(digest), 'cyan')
    print colored("integrity tag: " + str(signature), 'cyan')
    return digest == signature


def add_new_padding(onion, old_padding, hostport, aes_key):
    dummy_padding = PBKDF2(
            aes_key,
            hostport,
            128,
            config.KDF_ITERATIONS)

    print colored("Padding generated with AES key: " + str(aes_key) + " and identifier: "
                  + str(unpackHostPort(hostport)[0]) + ":" + str(unpackHostPort(hostport)[1])
                  + " value:" + str(dummy_padding), 'cyan')

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


def add_new_onion_padding(nextmessage, hostport, aes_key):
    padding = PBKDF2(
            aes_key,
            hostport,
            144,
            config.KDF_ITERATIONS)
    print colored("Padding generated with AES key: " + str(aes_key) + " and identifier: "
                  + str(unpackHostPort(hostport)[0]) + ":" + str(unpackHostPort(hostport)[1])
                  + " value:" + str(padding), 'cyan')

    return nextmessage + padding
