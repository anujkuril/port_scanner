#!usr/bin/python3
import argparse
import socket
import threading

def connection_scan(target_ip,target_port):
	try:
		conn_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		conn_socket.connect((target_ip,target_port))
		#conn_socket.send(b'banner_query\r\n')
		print("[+]{}/tcp open".format(target_port))
	except OSError:
		print("[-]{}/tcp closed".format(target_port))
	finally:
		conn_socket.close()

def port_scan(target,port_num):
	try:
		target_ip = socket.gethostbyname(target)
		print("[+] scan result for: {}".format(target_ip))
		connection_scan(target_ip,int(port_num))
	except OSError:
		print("[-] cannont resolve {}: unknown host".format(target))
		return #exit scan if target ip is not resolved

def argument_parser():
	parser = argparse.ArgumentParser(description="TCP port scanner. Accept a hostname/ip adderss and list of port to scan. Attempt to identify the service running on port.")
	parser.add_argument("-o","--host", nargs="?", help="ip address")
	parser.add_argument("-p", "--port", nargs="?", help="comma-seperated port list, such as '80,22'")

	var_args = vars(parser.parse_args()) #convert argument namespace to dictionary

	return var_args

if __name__ == '__main__':
	try:
		# argument_parser()
		user_args = argument_parser()
		host = user_args["host"]
		port_list = user_args["port"].split(",") #make list from port number
		for port in port_list:
			port_scan(host,port)
	except AttributeError:
		print("Error. Please provide the command_line argument before running")
		argument_parser()
		# user_args = argument_parser()