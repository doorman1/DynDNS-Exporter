#!/usr/bin/env python

import os
import sys
import time
import re
import urllib2
import csv
import cPickle as pickle

ROOT = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(ROOT, 'vendor'))

import ipaddr

from settings import *

class CacheNotWritable(Exception):
	def __init__(self, value):
		self.value = value
	def __str__(self):
		return repr(self.value)

# Cache dictionary
cache = {}

# Query URL for City/ISP/Organization
query_url = 'http://geoip1.maxmind.com/f?l=' + license_key + '&i='

def cidr_to_ipv4(cidr):
	"""Convert cidr to ipaddr.IPv4Network object"""

	return ipaddr.IPv4Network(cidr)

# Convert private networks to ipaddr.IPv4Network objects
for name, networks in private_network_names.items():
	private_network_names[name] = map(cidr_to_ipv4, networks)

def cache_entry_valid(entry):
	"""Return False if cache entry has expired"""

	return (entry['timestamp'] + cache_lifetime*24*60*60) > int(time.time())

def cache_cleanup():
	"""Remove exprired cache entries"""

	for key in cache.keys():
		if not cache_entry_valid(cache[key]):
			del cache[key]

def cache_load():
	global cache
	if os.path.isfile(cache_file):
		try:
			cache = pickle.load(open(cache_file, 'rb'))
		except Exception, e:
			print >> sys.stderr, "Failed to load cache from file:", e
			return False
		cache_cleanup()
	return False

def cache_save():
	cache_cleanup()
	try:
		pickle.dump(cache, open(cache_file, 'wb'), pickle.HIGHEST_PROTOCOL)
	except Exception, e:
		print >> sys.stderr, "Failed to save cache to file:", e
		return False
	return True

if cache_enable:
	cache_load()
	if not cache_save():
		raise CacheNotWritable, "Cache is not writable"

def geoip_query(ip):
	"""Query Maxmind's web service"""

	try:
		return urllib2.urlopen(query_url + ip)
	except urllib2.URLError, e:
		print >> sys.stderr, "Query failed:", e
		raise

def ip_info(ip):
	"""Return a dictionary with information about a given IP address"""

	try:
		# Check if the IP is valid
		ipaddr.IPv4Address(ip)
	except (ipaddr.AddressValueError, ValueError):
		return None

	if cache_enable and cache.has_key(ip) and cache_entry_valid(cache[ip]):
		data = cache[ip]
	else:
		data = {}

		# Check if this IP belongs to a private network
		for name, networks in private_network_names.items():
			for network in networks:
				if ipaddr.IPv4Address(ip) in network:
					data['isp'] = name

		# Else, query MaxMind's web service
		if not data.has_key('isp'):
			try:
				handle = geoip_query(ip)
				csvreader = csv.reader(handle)
				row = csvreader.next()
			except (urllib2.URLError, csv.Error):
				return None

			# A length of 11 indicates that an error code
			# has been included in the response
			# We only print warnings for two fatal error codes, as
			# the rest errors are unlikely to occur or unimportant
			if len(row) == 11:
				if row[10] in ['INVALID_LICENSE_KEY', 'MAX_REQUESTS_PER_LICENSE']:
					print >> sys.stderr, "Fatal error:", row[10]
				return None

			# ISP is listed in the 9th column
			isp = row[8]
			# See if there is an alternate name specified for this ISP
			if isp_names_alt.has_key(isp):
				isp = isp_names_alt[isp]
			data['isp'] = isp

		# Store the retrieval time
		data['timestamp'] = int(time.time())

		if cache_enable:
			cache[ip] = data
			cache_save()

	return data

def ip_to_isp(ip):
	"""Return a string with the ISP of a given IP address"""

	data = ip_info(ip)

	if data:
		return data['isp']
	else:
		return 'N/A'
