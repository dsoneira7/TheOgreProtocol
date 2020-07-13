from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto import Random
import socket
import utils
import sys
import threading
import argparse
import signal
import os
import config
from termcolor import colored

portstring = ""
proxy = False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dbg", help="use public.pem and private.pem", action="store_true")
    parser.add_argument("--proxy", help="run as http proxy node", action="store_true")
    parser.add_argument("node_ip", help="the ip address of this node")
    parser.add_argument("portno", type=int, help="the port this node should listen on")
    parser.add_argument("dir_auth_ip", help="the ip address of the directory authority")
    parser.add_argument("dir_auth_port", type=int, help="the port number of the directory authority")
    args = parser.parse_args()
    global proxy
    proxy = args.proxy
    # Set up listening server
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    myip = args.node_ip  # loopback only for now
    s.bind((myip, args.portno))
    global portstring
    portstring = str(myip) + ":" + str(args.portno)
    s.listen(1)
    randfile = Random.new()

    print colored("N[" + portstring + "]: Node initialized...", 'cyan')

    # Generate RSA keys, register self with directory authority
    mykey = RSA.generate(1024)
    if args.dbg:
        f = open('private.pem', 'r')
        private = f.read()
        f.close()
        mykey = RSA.importKey(private)
    else:
        dir_auth = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        dir_auth.connect((args.dir_auth_ip, args.dir_auth_port))
        result = dir_auth.send("n")
        if result == 0:
            print colored(
                "N[" + portstring + "]: The directory authority went offline during registration! Terminating relay process...",
                'cyan')
            sys.exit(1)
        msg = utils.packHostPort(myip, args.portno) + mykey.exportKey(format="OpenSSH", passphrase=None, pkcs=1)
        result = utils.sendn(dir_auth, msg)
        # print result
        if result == 0:
            print colored(
                "N[" + portstring + "]: The directory authority went offline during registration! Terminating relay process...",
                'cyan')
        dir_auth.close()

    print colored("N[" + portstring + "]: Node has successfully been registered.", 'cyan')

    # The while condition here dictates how long the node is up
    while True:
        clientsocket, addr = s.accept()
        threading.Thread(target=startSession, args=(clientsocket, mykey, utils.packHostPort(myip, args.portno))).start()
        print colored("N[" + portstring + "]: New session started.", 'cyan')


def startSession(prevhop, mykey, my_hostport):
    # THREAD BOUNDARY
    # need this node to have its own key pair
    try:
        routemessage = utils.recv_message_with_length_prefix(prevhop)
    except socket.error, e:
        routemessage = ""
    if routemessage == "":
        # kill this thread
        return
    try:
        print colored("N[" + portstring + "]: Received new onion: " + str(routemessage), 'cyan')
        aeskey, hostport, nextmessage = peelRoute(routemessage[:(len(routemessage) - (config.HOP_LIMIT * 128))], mykey)
        if hostport == "0" * 8:
            this_is_destiny(nextmessage[:config.DATA_BLOCK_LENGTH])
            return

        print colored("N[" + portstring + "]: Next relay's address: " + utils.unpackHostPort(hostport)[0] + ":"
                      + str(utils.unpackHostPort(hostport)[1]), 'cyan')
        print colored("N[" + portstring + "]: Adding padding to the decrypted onion.", 'cyan')
        nextmessage = utils.add_new_onion_padding(nextmessage, my_hostport, aeskey)
        if not comprobe_padding(nextmessage, routemessage[(len(routemessage) - (config.HOP_LIMIT * 128)):], mykey,
                                aeskey):
            print colored("N[" + portstring + "]: Onion discarded.", 'cyan')
            return

        print colored("N[" + portstring + "]: The onion is honest. Proceeding to process the extension.", 'cyan')

    except ValueError:
        prevhop.shutdown(socket.SHUT_RDWR)
        return
    nextmessage = utils.add_new_padding(nextmessage, routemessage[(len(routemessage) - (config.HOP_LIMIT * 128)):],
                                        my_hostport, aeskey)
    nexthost, nextport = utils.unpackHostPort(hostport)
    nexthop = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    nexthop.connect((nexthost, nextport))
    if nextmessage != "":
        utils.send_message_with_length_prefix(nexthop, nextmessage)
    # spawn forwarding and backwarding threads here
    fwd = threading.Thread(target=forwardingLoop, args=(prevhop, nexthop, aeskey))
    bwd = threading.Thread(target=backwardingLoop, args=(prevhop, nexthop, aeskey))
    fwd.start()
    bwd.start()
    fwd.join()
    bwd.join()
    return


def this_is_destiny(message):
    message_length = int(message[:3])
    message = message[3:3 + message_length]
    print colored("N[" + portstring + "]: Anonymous message: " + message, 'cyan')


def forwardingLoop(prevhop, nexthop, aeskey):
    while True:
        try:
            message = utils.recv_message_with_length_prefix(prevhop)
        except socket.error, e:
            message = ""
        if message == "":
            # closing sockets may screw with other threads that use them
            try:
                prevhop.shutdown(socket.SHUT_RDWR)
                nexthop.shutdown(socket.SHUT_RDWR)
            except socket.error, e:
                pass
            return
        message = utils.peel_layer(message, aeskey)
        try:
            bytessent = utils.send_message_with_length_prefix(nexthop, message)
            print colored("N[" + portstring + "]: Hopped forwards", 'cyan')
        except socket.error, e:
            pass
        if bytessent == 0:
            print colored("N[" + portstring + "]: process " + str(os.getpid()) + " closing forwardingLoop", 'cyan')
            try:
                prevhop.shutdown(socket.SHUT_RDWR)
                nexthop.shutdown(socket.SHUT_RDWR)
            except socket.error, e:
                pass
            return


def backwardingLoop(prevhop, nexthop, aeskey):
    while True:
        message = ""

        try:
            message = utils.recv_message_with_length_prefix(nexthop)
        except socket.error, e:
            message = ""
        if message == "":
            # closing sockets may screw with other threads that use them
            try:
                prevhop.shutdown(socket.SHUT_RDWR)
                nexthop.shutdown(socket.SHUT_RDWR)
            except socket.error, e:
                pass
            return
        message = utils.add_layer(message, aeskey)
        bytessent = 0
        try:
            bytessent = utils.send_message_with_length_prefix(prevhop, message)
            print colored("N[" + portstring + "]: Hopped backwards", 'cyan')
        except socket.error, e:
            pass
        if bytessent == 0:
            try:
                prevhop.shutdown(socket.SHUT_RDWR)
                nexthop.shutdown(socket.SHUT_RDWR)
            except socket.error, e:
                pass
            return


def peelRoute(message, mykey):
    message, aeskey = utils.unwrap_message(message, mykey)

    print colored("N[" + portstring + "]: Unwrapping the received onion to extract AES key and next node's address",
                  'cyan')

    hostport = utils.unpad_message(message[:16])
    nextmessage = message[16:]  # if nextmessage is an empty string, I'm an exit node
    return aeskey, hostport, nextmessage


def comprobe_padding(onion, padding, rsa_key, aes_key):
    print colored("N[" + portstring + "]: Proceeding to verify the integrity tag... ", 'cyan')
    encrypted_signature = padding[:128]
    signed = onion + padding[128:]
    print str(padding[128:])
    pointer = 0

    """For some reason, sometimes when transmitting a large message, the received onion in some of the nodes is not 
    equal to the one that was generated in the client. We don't know why this happens, but we discovered that if we
    dissassemble and reassemble the onion, the problem apparently disappears. So that is what the next while block 
    does"""

    reconstruct = ""
    while pointer < len(signed):
        if pointer + 16 < len(signed):
            actual = signed[pointer:(pointer + 16)]
        else:
            actual = signed[pointer:]
        pointer += 16
        reconstruct += actual
    decrypted_signature = rsa_key.decrypt(encrypted_signature)
    if not utils.verify(aes_key, signed, decrypted_signature):
        return False
    return True


if __name__ == "__main__":
    main()
