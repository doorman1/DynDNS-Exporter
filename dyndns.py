#!/usr/bin/env python

import os
import sys
import cookielib
import urllib2
import urllib
import re
import time
import json
import smtplib
from email.mime.text import MIMEText
from collections import deque
import xml.sax.saxutils as saxutils

ROOT = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(ROOT, 'vendor'))

from BeautifulSoup import BeautifulSoup

from dyndns_geoip import ip_to_isp
from portcheck import (
	query_hosts, ping_hosts, split_into_offline_online_private)

from settings import *

# Additional fields to add, based on the IP address
# This only works with A-records
# Line format:
#    (title, callback function)
additional_fields = (
	('ISP', ip_to_isp),
)
# Where should these additional columns be inserted?
# Values are between 1 and 3 (or 4, if display_type is set to True)
additional_fields_position = 2
# Maximum length for additional columns
additional_fields_length = 20

base_path = os.path.dirname(__file__)

urls = {
	'home' : 'http://dyn.com/',
	'account' : 'https://account.dyn.com/',
	'login' : 'https://account.dyn.com/entrance/',
	'zonedns' : 'https://account.dyn.com/dns/dyn-standard-dns/'
}

if display_type:
	titles = ['Hostname', 'Service', 'Details', 'Last Updated']
else:
	titles = ['Hostname', 'Details', 'Last Updated']

for afield in reversed(additional_fields):
	titles.insert(additional_fields_position, afield[0])

# Cookie storage
cookie_jar = cookielib.LWPCookieJar()
cookie_file = 'dyndns.cookie'
save_cookie = False

if os.path.isfile(cookie_file):
	cookie_jar.load(cookie_file)

def setup():
	"""Configure urllib2 to use cookies"""

	handler = urllib2.HTTPCookieProcessor(cookie_jar)
	opener = urllib2.build_opener(handler)
	urllib2.install_opener(opener)

def request(url, data, header):
	"""Do an HTTP request and return a handle to it"""

	try:
		req = urllib2.Request(url, data, header)
		handle = urllib2.urlopen(req)
		if save_cookie:
			cookie_jar.save(cookie_file)
		return handle
	except IOError:
		return None

def get(url, data = None, _header = None):
	"""Access a page via the GET method"""

	if isinstance(data, str):
		url += '?' + data

	header = {
		'User-agent' : 'DynDns.py/1.0 (X11; U; Linux i686; en-US; rv:1.7)',
		'Referer' : urls['home'],
	}
	if isinstance(_header, dict):
		header.update(_header)

	return request(url, None, header)

def post(url, data = None, _header = None):
	"""Access a page via the POST method"""

	if isinstance(data, dict):
		data = urllib.urlencode(data)

	header = {
		'User-agent' : 'DynDns.py/1.0 (X11; U; Linux i686; en-US; rv:1.7)',
		'Referer' : urls['home'],
		'Content-Type' : 'application/x-www-form-urlencoded'
	}
	if isinstance(_header, dict):
		header.update(_header)

	return request(url, data, header)

def current_datetime():
	"""Return the current date/time as a string"""

	return time.strftime("%a, %d %b %Y %I:%M:%S %p %Z (%z)")

def hostname_links(hostname):
	"""Return <a> tags pointing to the hostname and ports specified"""

	links = []
	for port, protocol in ports:
		links.append('[<a href="%s://%s%s/" rel="external">%s</a>]' % (
		              protocol, hostname, (':' + str(port), '')[port == 80],
		              port))
	return '<span class="links">' + ' '.join(links) + '</span>'

def login():
	"""Login procedure"""

	# DynDNS.com has introduced a new token in the login form, a hidden input
	# element with the name 'multiform'. We need to retrieve its value.
	soup = BeautifulSoup(get(urls['login']).read())
	login_form = soup.find('form', {'id' : re.compile('^login[0-9]*')})
	multiform = login_form.find('input', {'name' : 'multiform'})

	data = {
		'username' : auth_cred['username'],
		'password' : auth_cred['password'],
		'multiform' : multiform['value']
	}

	return post(urls['login'], data)

def logout():
	"""Logout procedure"""

	return get(urls['home'], '__logout=1')

def logged_in():
	"""Return True if we're logged in, False otherwise"""

	page = get(urls['account']).read()
	# If there is no 'Forgot your password?' text on the page, then we're
	# logged in.
	return re.search('Forgot your password?', page) is None

def zone_page(zone):
	"""Retrieve the zone page"""

	return get(urls['zonedns'] + zone).read()

def store_results_txt(res, loc, zone):
	"""Store the results as a TXT file"""

	try:
		f = open(loc, 'w')
	except Exception, e:
		print >> sys.stderr, e
		return False

	res = deque(res)
	res.appendleft(['-' * len(title) for title in titles])
	res.appendleft(titles)

	col_paddings = []
	for i in range(len(res[0])):
		col_paddings.append(max(len(row[i]) for row in res))

	print >> f, "Zone information for %s\n" % zone

	for row in res:
		for col in range(len(res[0])):
			print >> f, row[col].ljust(col_paddings[col] + 2),
		print >> f

	print >> f, "\nLast update: " + current_datetime(),

	f.close()

def store_results_html(res, loc, zone, offline, online, private):
	"""Store the results as a HTML file"""

	try:
		f = open(loc, 'w')
	except Exception, e:
		print >> sys.stderr, e
		return False

	for i in range(len(res)):
		res[i] = map(saxutils.escape, res[i])

		for j in range(additional_fields_position,
		               additional_fields_position + len(additional_fields)):
			if len(res[i][j]) > additional_fields_length + 1:
				res[i][j] = '<abbr title="%s">%s&hellip;</abbr>' % (
					res[i][j],
					res[i][j][:additional_fields_length]
				)

	table = "<table>\n"
	table += '<tr><th>' + '</th><th>'.join(titles) + "</th></tr>\n"
	for i in range(len(res)):
		hostname = res[i][0]
		status = ''
		if hostname in offline:
			status = 'offline'
		elif hostname in online:
			status = 'online'
		elif hostname in private:
			status = 'private'
		table += ('<tr class="' + ['odd', 'even'][i % 2] + '">' +
		          '<td class="hostname ' + status + '">' +
		          '</td><td>'.join([res[i][0] + ' ' +
		                            hostname_links(res[i][0])] + res[i][1:]) +
		          "</td></tr>\n")
	table += '</table>'

	template = open(os.path.join(base_path, 'template.html')).read()
	template = template.replace('[ZONE]', zone)
	template = template.replace('[ZONE_INFO]', table)
	template = template.replace('[LAST_UPDATE]', current_datetime())

	f.write(template)
	f.close()

def export_zones():
	"""Export all zones defined in the zones dictionary"""

	for zone in zones:
		page = zone_page(zone[0])
		soup = BeautifulSoup(page)
		# Find the table with the hostnames
		for tbl in soup.findAll('table'):
			if tbl.find('th') and tbl.find('th').string == 'Hostname':
				table = tbl
				break
		else:
			continue
		rows = table.findAll('tr')[1:]

		results = []
		for row in rows:
			cols = row.findAll('td')
			results.append([col.find(text = True).strip() for col in cols])
			# Skip wildcard hostnames
			if results[-1][0].startswith('*'):
				results.pop()
				continue
			if 'Blocked for abuse.' in results[-1][2]:
				ip_addr = None
				results[-1][2] = 'Blocked for abuse.'
				results[-1].append('---')
			elif results[-1][1] == 'A-record':
				ip_addr = results[-1][2]
			else:
				ip_addr = None
			if not set([results[-1][1], 'All']).intersection(set(exported_types)):
				results.pop()
				continue
			elif not display_type:
				del results[-1][1]

			if ip_addr:
				afields = []
				for afield in additional_fields:
					afields.append(afield[1](ip_addr))
			else:
				afields = ['---'] * len(additional_fields)
			for afield in reversed(afields):
				results[-1].insert(additional_fields_position, afield)

		# Check host statuses (offline/online/private)
		hosts = [result[0] for result in results]
		statuses = query_hosts(hosts, port_checks)
		offline, online, private = split_into_offline_online_private(statuses)

		if ping_offline_hosts and offline:
			ping_statuses = ping_hosts(offline)
			reachable = dict(
				(hostname, ports) for hostname, ports in offline.iteritems()
				if ping_statuses[hostname])
			for hostname in reachable:
				online[hostname] = offline[hostname]
				del offline[hostname]

		# Load old host statuses if available
		json_file = os.path.splitext(zone[1])[0] + '.json'
		try:
			with open(json_file) as infile:
				old_statuses = json.load(infile)
		except IOError:
			old_statuses = None

		# Save new host statuses in JSON format
		new_statuses = {
			'offline': offline.keys(),
			'online': online.keys(),
			'private': private.keys(),
		}
		with open(json_file, 'w') as outfile:
			json.dump(new_statuses, outfile)

		# Send out status change notification emails
		if all([email_enable, email_sender, email_recipient, old_statuses]):
			if email_use_ssl:
				server = smtplib.SMTP_SSL(email_host, email_port)
			else:
				server = smtplib.SMTP(email_host, email_port)

			if email_use_tls:
				server.ehlo()
				server.starttls()
				server.ehlo()

			if email_host_user and email_host_password:
				server.login(email_host_user, email_host_password)

			for status_change in email_status_changes:
				old_status, new_status, status_enable = status_change

				if not status_enable:
					continue

				matched_hosts = set(old_statuses[old_status]).intersection(
					new_statuses[new_status])

				text_replacements = {
					'{new_status}': new_status.upper(),
					'{old_status}': old_status.upper(),
					'{timestamp}': current_datetime(),
				}

				for host in matched_hosts:
					subject = email_subject.strip()
					message = email_message.strip()

					text_replacements.update({'{hostname}': host})

					for text_replacement in text_replacements.iteritems():
						subject = subject.replace(
							text_replacement[0], text_replacement[1])
						message = message.replace(
							text_replacement[0], text_replacement[1])

					msg = MIMEText(message)
					msg['Subject'] = subject
					msg['From'] = email_sender
					msg['To'] = email_recipient

					server.sendmail(
						email_sender, [email_recipient], msg.as_string())

			server.quit()

		if zone[1].endswith('.html'):
			store_results_html(
				results, zone[1], zone[0], offline, online, private)
		else:
			store_results_txt(results, zone[1], zone[0])

if __name__ == '__main__':
	setup()
	login()
	if not logged_in():
		print >> sys.stderr, "Login failed, check your credentials!"
		sys.exit(1)
	export_zones()
	logout()
