import sys
import subprocess
import os
import argparse
import random
import time
import signal
import utils

signal.signal(signal.SIGINT, utils.signal_handler)

num_relays = 3
num_exits = 2

parser = argparse.ArgumentParser()
parser.add_argument("dir_auth_ip", help="the ip address of the directory authority")
parser.add_argument("dir_auth_port", type=int, help="the port number of the directory authority")
parser.add_argument("dest_ip", help="the ip address of the client's destination")
parser.add_argument("dest_port", type=int, help="the port number of the client's destination")
args = parser.parse_args()

os.system("python directory_authority.py " + args.dir_auth_ip + " " + str(args.dir_auth_port) + " &")
#wait for directory authority to spin up
time.sleep(1)

port_range = range(7000,9000)
ports = random.sample(port_range,num_relays+num_exits)
exit_port = "6666"
for port in ports[:num_relays]:
	os.system("python node.py " + str(port) + " " + args.dir_auth_ip + " " + str(args.dir_auth_port) + " &")
	time.sleep(1)
#TODO: May be necessary to change how the ip address of each node is configured.
for port in ports[-1*num_exits:]:
	os.system("python node.py " + args.dir_auth_ip + " " + str(port) + " " + args.dir_auth_ip + " " + str(args.dir_auth_port) + " --exit &")
	time.sleep(1)

os.system("python client.py " + " " + args.dir_auth_ip + " " + str(args.dir_auth_port) + " " + args.dir_auth_ip + " " +str(args.dest_port))#+ " &")