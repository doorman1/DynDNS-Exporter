#!/usr/bin/env python

import os
import sys
import collections
import multiprocessing.dummy
import socket
import subprocess

ROOT = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(ROOT, 'vendor'))

import ipaddr

from settings import *

# Set default timeout for port checks and other sockets (e.g. DNS lookups)
socket.setdefaulttimeout(timeout)

private_networks = map(ipaddr.IPv4Network, private_networks)

private_hostname_cache = {}

def hostname_is_private(hostname):
	"""Check whether a hostname has an address belonging to a private network.
	"""

	# Check based on hostname
	if hostname in private_hostnames:
		return True

	# Check based on IP
	if hostname not in private_hostname_cache:
		try:
			addr = socket.gethostbyname(hostname)
		except socket.gaierror:
			private_hostname_cache[hostname] = None
		else:
			addr = ipaddr.IPv4Address(addr)
			private_hostname_cache[hostname] = (
				bool(sum([addr in net for net in private_networks])))

	return private_hostname_cache[hostname]

def query_single_host(args):
	"""Query a single host port to check if it's reachable.
	"""

	hostname, port = args

	if hostname_is_private(hostname):
		port_status = None
	else:
		sock = socket.socket()

		try:
			sock.connect((hostname, port))
		except:
			port_status = None
		else:
			sock.close()
			port_status = True

		sock.close()

	return hostname, port, port_status

def query_hosts(hosts, ports):
	"""Try to contact the hosts and return the port statuses in a
	{hostname1: {port1: port_status, ...}, ...} dictionary.
	"""

	pool = multiprocessing.dummy.Pool(port_thread_pool_size)

	hostname_port_list = [
		(hostname, port)
		for hostname in hosts for port in ports]

	port_statuses = pool.map(query_single_host, hostname_port_list)

	pool.close()
	pool.join()

	statuses = collections.defaultdict(dict)
	for port_status in port_statuses:
		statuses[port_status[0]][port_status[1]] = port_status[2]

	return statuses

def ping_single_host(hostname):
	"""Ping a single host to determine whether it's online.
	"""

	with open(os.devnull, 'w') as fnull:
		ret = subprocess.call(
			ping_cmd + [hostname], stdout=fnull, stderr=subprocess.STDOUT)

	return hostname, ret == 0

def ping_hosts(hosts):
	"""Ping the hosts and return a dictionary with their statuses.
	"""

	pool = multiprocessing.dummy.Pool(ping_thread_pool_size)

	ping_statuses = pool.map(ping_single_host, hosts)

	pool.close()
	pool.join()

	statuses = collections.defaultdict(dict)
	for hostname, status in ping_statuses:
		statuses[hostname] = status

	return statuses

def split_into_offline_online_private(statuses):
	"""Categorize the hosts based on their IP and port status.
	"""

	offline = {}
	online = {}
	private = {}

	for hostname, ports in statuses.iteritems():
		if hostname_is_private(hostname):
			private[hostname] = ports
		else:
			if len([code for code in ports.values() if code is not None]):
				online[hostname] = ports
			else:
				offline[hostname] = ports

	return offline, online, private
