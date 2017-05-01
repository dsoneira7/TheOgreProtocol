from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto import Random
import socket
from signatures import sign,verify
import utils
import sys
import threading
import argparse
import signal
import os

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--exit", help="run as an exit node", action="store_true")
    parser.add_argument("--dbg", help="use public.pem and private.pem", action="store_true")
    parser.add_argument("portno", type=int, help="the port this node should listen on")
    parser.add_argument("dir_auth_ip", help="the ip address of the directory authority")
    parser.add_argument("dir_auth_port", type=int, help="the port number of the directory authority")
    args = parser.parse_args()

    # Set up listening server
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    myip = '127.0.0.1' #loopback only for now
    s.bind((myip, args.portno))
    s.listen(1)
    randfile = Random.new()

    # Generate RSA keys, register self with directory authority
    mykey = RSA.generate(1024)
    if args.dbg:
        # f = open('public.pem', 'r')
        # public = f.read()
        # f.close()
        f = open('private.pem', 'r')
        private = f.read()
        f.close()
        # mykey = RSA.importKey(public)
        mykey = RSA.importKey(private)
    else:
        dir_auth = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        dir_auth.connect((args.dir_auth_ip, args.dir_auth_port))
        result = 0
        # send an 'e' for exit node here, 'n' for relay node
        if args.exit:
            result = dir_auth.send("e")
        else:
            result = dir_auth.send("n")
        if result == 0:
            print "The directory authority went offline during registration! Terminating relay process..."
            sys.exit(1)
        result = utils.sendn(dir_auth, mykey.exportKey(format = "OpenSSH", passphrase=None, pkcs = 1))
        # print result
        if result == 0:
            print "The directory authority went offline during registration! Terminating relay process..."
        dir_auth.close()

    print "Successfully registered! Process " + str(os.getpid()) + " is listening for client connections on port " + str(args.portno)

    #TODO replace this old code
    # Listen for connections
    maxsessions = 1
    numsessions = 0
    #The while condition here dictates how long the node is up
    while numsessions < maxsessions:#True:
        clientsocket, addr = s.accept()
        print "New session starting on process " + str(os.getpid())
        threading.Thread(target=startSession, args=(clientsocket, mykey, args.exit)).start()
        numsessions += 1

def startSession(prevhop, mykey, is_exit):
    #print "Node got contact from client! Starting session!"
    # THREAD BOUNDARY
    # need this node to have its own key pair
    routemessage = utils.recv_message_with_length_prefix(prevhop)
    if routemessage == "":
        #kill this thread
        return
    aeskey, hostport, nextmessage = peelRoute(routemessage, mykey)
    nexthost, nextport = utils.unpackHostPort(hostport)
    nexthop = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    nexthop.connect((nexthost, nextport))
    if nextmessage != "":
        utils.send_message_with_length_prefix(nexthop, nextmessage)
    #spawn forwarding and backwarding threads here
    fwd = threading.Thread(target=forwardingLoop, args=(prevhop, nexthop, aeskey))
    bwd = threading.Thread(target=backwardingLoop, args=(prevhop, nexthop, aeskey, is_exit))
    fwd.start()
    bwd.start()
    fwd.join()
    bwd.join()
    #print "node process " + str(os.getpid()) + " is closing! Bye bye!"
    return

def forwardingLoop(prevhop, nexthop, aeskey):
    while True:
        message = utils.recv_message_with_length_prefix(prevhop)
        if message == "":
            #closing sockets may screw with other threads that use them
            #print "process " + str(os.getpid()) + " closing forwardingLoop"
            try:
                prevhop.shutdown(socket.SHUT_RDWR)
                nexthop.shutdown(socket.SHUT_RDWR)
            except socket.error, e:
                pass
            return
        # unwrap the message or something - in spec
        #print "process " + str(os.getpid()) + "got message: " + message
        message = utils.peel_layer(message, aeskey)
        bytessent = 0
        try:
            bytessent = utils.send_message_with_length_prefix(nexthop, message)
        except socket.error, e:
            pass
        if bytessent == 0:
            #print "process " + str(os.getpid()) + " closing forwardingLoop"
            try:
                prevhop.shutdown(socket.SHUT_RDWR)
                nexthop.shutdown(socket.SHUT_RDWR)
            except socket.error, e:
                pass
            return

def backwardingLoop(prevhop, nexthop, aeskey, is_exit=False):
    while True:
        message = utils.recv_message_with_length_prefix(nexthop)
        if message == "":
            #closing sockets may screw with other threads that use them
            #print "process " + str(os.getpid()) + " closing backwardingLoop"
            try:
                prevhop.shutdown(socket.SHUT_RDWR)
                nexthop.shutdown(socket.SHUT_RDWR)
            except socket.error, e:
                pass
            return
        # wrap the message or something - in spec
        if(is_exit):
            message = utils.add_layer(utils.pad_message(message), aeskey)
        else:
            message = utils.add_layer(message, aeskey)
        bytessent = 0
        try:
            bytessent = utils.send_message_with_length_prefix(prevhop, message)
        except socket.error, e:
            pass
        if bytessent == 0:
            #print "process " + str(os.getpid()) + "closing backwardingLoop"
            try:
                prevhop.shutdown(socket.SHUT_RDWR)
                nexthop.shutdown(socket.SHUT_RDWR)
            except socket.error, e:
                pass
            return

def peelRoute(message, mykey):
    message, aeskey = utils.unwrap_message(message, mykey)
    host, port = utils.unpackHostPort(message[:8])
    #print "host: " + host + ", port: " + str(port) + "pid: " + str(os.getpid())
    hostport = message[:8]
    nextmessage = message[8:] #if nextmessage is an empty string, I'm an exit node
    return (aeskey, hostport, nextmessage)


if __name__ == "__main__":
    main()
