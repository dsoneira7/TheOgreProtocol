from Crypto.PublicKey import RSA
from Crypto import Random
import socket
import argparse
import utils
from termcolor import colored
from datetime import datetime

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("dir_auth_ip", help="the ip address of the directory authority")
    parser.add_argument("dir_auth_port", help="the port number of the directory authority")
    args = parser.parse_args()

    print colored("Client started.", 'yellow')

    da_file = open('dir_auth_pub_key.pem', 'r')
    da_pub_key = da_file.read()
    da_pub_key = RSA.importKey(da_pub_key)

    while True:
        print "Type the identifier of the destiny node[ip_address:port]:"
        destiny = raw_input()
        (destiny_address, destiny_port) = destiny.split(":")
        print "Type the message you want to send:"
        message = raw_input()
        if message == "":
            quit()

        print colored("Sending route request to directory authority in " + args.dir_auth_ip + ":" + args.dir_auth_port
                      + "...", 'yellow')
        for i in range(0,10):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((args.dir_auth_ip, int(args.dir_auth_port)))
            s.send('r')  # specify request type (route)

            # construct and send an aes key
            randfile = Random.new()
            aes_key = randfile.read(32)
            print utils.packHostPort(destiny_address, int(destiny_port))
            da_route_request = utils.packHostPort(destiny_address, int(destiny_port)) + aes_key
            da_route_message = da_pub_key.encrypt(da_route_request, 0)[0]
            succ = utils.send_message_with_length_prefix(s, da_route_message)
            if not succ:
                s.close()
                print colored("Directory authority connection failed", 'yellow')
                quit()
            else:
                print colored("Connection successful.", 'yellow')

            # Receive
            data = utils.recv_message_with_length_prefix(
                s)  # All info from directory authority
            if data == "":
                s.close()
                print colored("Directory authority connection failed", 'yellow')
                quit()
            start = datetime.now()
            print colored("Starting wrapping process: " + str(start), 'yellow')
            hop_data = utils.aes_decrypt(data, aes_key)

            # hoplist format (ip, port, public_key)
            # Replace this with processed route and key data
            hoplist = utils.process_route(hop_data)

            print colored("Obtained route:", 'yellow')
            count = 1
            for b in hoplist:
                print colored("P" + str(count) + ": " + str(b[0]) + ":" + str(b[1]), 'yellow')
                count += 1

            hoplist = list(reversed(hoplist))

            wrapped_message, aes_key_list = utils.wrap_all_messages(hoplist, message)

            finish = datetime.now()
            print colored("Finish wrapping process: " + str(finish), 'yellow')

            if i == 0:
                total = finish - start
            else:
                total += (finish - start)

        print colored("Finish everything: " + str(total), 'yellow')
        # Send keys and establish link
        # run_client(hoplist, message)


def run_client(hoplist, message):
    next_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    next_host = (hoplist[len(hoplist) - 1][0], hoplist[len(hoplist) - 1][1])
    next_s.connect(next_host)
    # Generate wrapped message
    wrapped_message, aes_key_list = utils.wrap_all_messages(
        hoplist, message)

    utils.send_message_with_length_prefix(next_s, wrapped_message)


if __name__ == "__main__":
    main()
