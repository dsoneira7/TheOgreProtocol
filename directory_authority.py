from Crypto.PublicKey import RSA
from Crypto import Random
import socket
import argparse
import random
import utils
import config
from termcolor import colored


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("dir_auth_ip", help="the ip address of the directory authority")
    parser.add_argument("dir_auth_port", help="the port number of the directory authority")
    args = parser.parse_args()

    print colored("DA[" + args.dir_auth_ip + ":" + args.dir_auth_port + "]: Directory authority server started...", 'green')

    RSA_KEY_SIZE = 212

    relay_nodes = {}

    randfile = Random.new()

    # get the DA private key from a file
    da_file = open('dir_auth_priv_key.pem', 'r')
    da_private = da_file.read()
    da_mykey = RSA.importKey(da_private)

    # read in Port from command line args
    da_IP = args.dir_auth_ip
    da_port = args.dir_auth_port

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((da_IP, int(da_port)))
    s.listen(1)

    while True:
        # listen for connections and serve requests:
        # Register relay nodes with IP, Port, PublicKey in NodeDict
        # Register exit nodes with IP, Port PublicKey in ExitDict
        # Provide route of N nodes and 1 exit node, with IP, Port, PublicKey for every node

        (clientsocket, addr) = s.accept()

        request_type = clientsocket.recv(1)
        if request_type == "":
            clientsocket.close()
            continue

        if request_type == 'n':  # relay node
            msg = utils.recvn(clientsocket, RSA_KEY_SIZE + 8)
            if msg == "":
                clientsocket.close()
                continue
            node_addr = msg[:8]
            key = msg[8:]
            relay_nodes[node_addr] = key
            print colored(
                "DA[" + args.dir_auth_ip + ":" + args.dir_auth_port + "]: registered a relay node on ip:port " +
                str(utils.unpackHostPort(node_addr)[0]) + ":" + str(utils.unpackHostPort(node_addr)[1]),
                'green')

        elif request_type == 'r':  # route

            print colored("DA[" + args.dir_auth_ip + ":" + args.dir_auth_port + "]: Received a route request.", 'green')

            # recieve encrypted aes key from client
            data = utils.recv_message_with_length_prefix(clientsocket)
            if data == "":
                clientsocket.close()
                continue
            data_decrypted = da_mykey.decrypt(data)
            destination = data_decrypted[:8]
            aes_key = data_decrypted[8:]
            print destination
            for a in relay_nodes:
                if a == destination:
                    exit_node = (a, relay_nodes[a])

            clean_route = True
            if len(relay_nodes) > config.NUM_NODES:
                while clean_route:
                    clean_route = False
                    relay_list = random.sample(relay_nodes.items(), config.NUM_NODES)
                    for a in relay_list:
                        if a == destination:
                            clean_route = True
            else:
                relay_list = random.sample(relay_nodes.items(), config.NUM_NODES)

            # Uncomment if we want random length routes
            # relay_list = random.sample(relay_nodes.items(), random.randint(1, config.HOP_LIMIT)

            route_message = construct_route(relay_list, exit_node)

            blob = utils.aes_encrypt(utils.pad_message(route_message), aes_key)
            utils.send_message_with_length_prefix(clientsocket, blob)
            print colored("DA[" + args.dir_auth_ip + ":" + args.dir_auth_port + "]: sent a route to a client", 'green')

        clientsocket.close()


def construct_route(relays, exit_node):
    message = ""
    for a, b in relays:
        message += a + b
    message += exit_node[0] + exit_node[1]
    return message


if __name__ == "__main__":
    main()
