#!/usr/bin/python
#
# Copyright (c) 2017, IBM Corp
#
# AIX SUMA module for Ansible :
# https://github.com/ansible-aix/patch_mgmt
#
# This file is part of Ansible,
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

######################################################################

DOCUMENTATION = '''
---
module: aix_flrtvc
author: "Jerome Hurstel"
version_added: "1.0.0"
requirements: [ AIX ]

'''

import logging
import os
import re
import csv
import subprocess
import threading
import urllib
import ssl
import shutil

thrds = []

def start_threaded(thrds):
	def wrapper(func):
		def inner_wrapper(*args, **kwargs):
			p = threading.Thread(target=func, args=(args))
			logging.debug('[{}] Start thread {}'.format(func.__name__, p))
			p.start()
			thrds.append(p)
		return inner_wrapper
	return wrapper

def wait_threaded(thrds):
	def wrapper(func):
		def inner_wrapper(*args, **kwargs):
			[p.join() for p in thrds]
		return inner_wrapper
	return wrapper

def logged(func):
	def wrapper(*args, **kwargs):
		logging.debug('[{}] ENTER with {}'.format(func.__name__, args))
		res = func(*args, **kwargs)
		logging.debug('[{}] EXIT with {}'.format(func.__name__, res))
		return res
	return wrapper

def download(src, dst):
	"""
	Download efix from url to directory
	args:
		src (str): The url to download
		dst	(str): The absolute destination filename
	"""
	res = True
	if not os.path.isfile(dst):
		try:
			logging.debug('Downloading {} to {}...'.format(src, dst))
			subprocess.check_output(args=['/bin/wget', '--no-check-certificate', src, '-P', os.path.dirname(dst)], stderr=subprocess.STDOUT)
		except subprocess.CalledProcessError as e:
			logging.warn('[{}] EXCEPTION cmd={} rc={} output={}'.format(__name__, e.cmd, e.returncode, e.output))
			res = False
	return res
	
	# context = ssl._create_unverified_context()
	# filename = os.path.join(url, epkg)

	# logging.debug('Downloading {} to {}...'.format(filename, epkg))
	# try:
		# response = urllib.urlopen(filename, context=context)
	# except Exception as e:
		# logging.debug('EXCEPTION {}'.format(e))
	# logging.debug('DONE OPENING')
	# with open(os.path.join(epkg), 'w') as f:
		# while True:
			# chunk = response.read(1024*16)
			# if not chunk: break
			# f.write(chunk)
	# #urllib.urlretrieve(filename, epkg)
	# logging.debug('DONE WRITING')
	# return True

def check_prereq(epkg, ref):
	"""
	Check efix prerequisites based on fileset current level
	args:
	    dir  (str): The directory to store efixes
		epkg (str): The efix to check
		ref	 (str): The filename with reference fileset levels
	"""
	# Get fileset prerequisites
	stdout = ''
	try:
		cmd = '/usr/sbin/emgr -dXv3 -e {} | /bin/grep -p \\\"PREREQ'.format(epkg)
		stdout = subprocess.check_output(args=cmd, shell=True, stderr=subprocess.STDOUT)
	except subprocess.CalledProcessError as e:
		logging.warn('[{}] EXCEPTION cmd={} rc={} output={}'.format(__name__, e.cmd, e.returncode, e.output))

	res = False
	# For each prerequisites, ...
	for line in stdout.splitlines()[3:]:

		# ... skip comments and empty lines ...
		line = line.rstrip()
		if line and not line.startswith('#'):
		
			# ... match prerequisite ...
			match = re.match(r'^(.*?)\s+(.*?)\s+(.*?)$', line)
			if match is not None:
				(fileset, min, max) = match.groups()

				# ... extract current fileset level ...
				with open(os.path.abspath(os.path.join(os.sep, ref)),'r') as f:
					for l in f:
						if fileset in l:
							cur = l.split(':')[2]

							# ... and compare to min/max levels.
							logging.debug('{} {} {} {}'.format(fileset, min, cur, max))
							if min <= cur and cur <= max:
								res = True
							break
	return res

@logged
def run_lslpp(machine, file):
	"""
	Run command lslpp on a target system
	args:
		machine (str): The remote machine name
		file	(str): The filename to store stdout
	"""
	try:
		cmd = ['/usr/lpp/bos.sysmgt/nim/methods/c_rsh', machine, '/bin/lslpp -Lcq']
		stdout = subprocess.check_output(args=cmd, stderr=subprocess.STDOUT)
		with open(file,'w') as f: f.write(stdout)
	except subprocess.CalledProcessError as e:
		logging.warn('[{}] EXCEPTION cmd={} rc={} output={}'.format(__name__, e.cmd, e.returncode, e.output))

@logged
def run_emgr(machine, file):
	"""
	Run command emgr on a target system
	args:
		machine (str): The remote machine name
		file	(str): The filename to store stdout
	"""
	try:
		cmd = ['/usr/lpp/bos.sysmgt/nim/methods/c_rsh', machine, '/usr/sbin/emgr -lv3']
		stdout = subprocess.check_output(args=cmd, stderr=subprocess.STDOUT)
		with open(file,'w') as f: f.write(stdout)
	except subprocess.CalledProcessError as e:
		logging.warn('[{}] EXCEPTION cmd={} rc={} output={}'.format(__name__, e.cmd, e.returncode, e.output))

@start_threaded(thrds)
@logged
def run_flrtvc(machine, output, apar, csv, filesets, path, verbose):
	"""
	Run command flrtvc on a target system
	args:
		machine (str): The remote machine name
		output	(dict): The result of the command
	"""

	# Run 'lslpp -Lcq' on the remote machine and save to file
	lslpp_file = 'lslpp_{}.txt'.format(machine)
	p1 = threading.Thread(target=run_lslpp, args=(machine, lslpp_file))
	p1.start()

	# Run 'emgr -lv3' on the remote machine and save to file
	emgr_file = 'emgr_{}.txt'.format(machine)
	p2 = threading.Thread(target=run_emgr, args=(machine, emgr_file))
	p2.start()

	# Wait threads to finish
	p1.join()
	p2.join()

	# Prepare flrtvc command
	cmd = ['/usr/bin/flrtvc.ksh', '-e', emgr_file, '-l', lslpp_file]
	if apar and apar != 'all': cmd += ['-t', apar]
	if csv:	cmd += ['-f', csv]
	if filesets: cmd += ['-g', filesets]

	# Run flrtvc in compact and verbose mode
	try:
		stdout_c = subprocess.check_output(args=cmd, stderr=subprocess.STDOUT)
		stdout_v = subprocess.check_output(args=cmd+['-v'], stderr=subprocess.STDOUT)
	except subprocess.CalledProcessError as e:
		logging.warn('[{}] EXCEPTION cmd={} rc={} output={}'.format(__name__, e.cmd, e.returncode, e.output))

	# Save to variable ('flrtvc_c' value is used in run_parser func)
	output.update({ 'flrtvc_report': stdout_c.splitlines() })

	# Save to file
	if path:
		stdout = stdout_c
		if verbose: stdout = stdout_v
		if not os.path.exists(path): os.makedirs(path)
		with open(os.path.join(path, 'flrtvc_{}.txt'.format(machine)),'w') as f: f.write(stdout)

@start_threaded(thrds)
@logged
def run_parser(machine, output, report):
	"""
	Parse report by extracting URLs
	args:
		machine (str): The remote machine name
		output	(dict): The result of the command
		report	(str): The compact report
	"""
	reader_list = csv.DictReader(report, delimiter='|')
	rows = [row['Download URL'] for row in reader_list if re.match(r'^(http|https|ftp)://(aix.software.ibm.com|public.dhe.ibm.com)/(aix/ifixes/.*?/|aix/efixes/security/.*?.tar)$', row['Download URL']) is not None]
	rows = list(set(rows)) # remove duplicates
	output.update({ 'extracted_urls': rows })

@start_threaded(thrds)
@logged
def run_downloader(machine, output, urls):
	"""
	Download URLs and check efixes
	args:
		machine (str): The remote machine name
		output	(dict): The result of the command
		urls	(list): The list of URLs to download
	"""
	out = { 'epkgs': [], 'epkgs_dl_ok': [], 'epkgs_ck_ok': [] }
	for url in urls:
		protocol, srv, dir, name = re.search(r'^(.*?)://(.*?)/(.*)/(.*)$', url).groups()
		logging.debug('protocol={}, srv={}, dir={}, name={}'.format(protocol, srv, dir, name))
		if '.epkg.Z' in name:
			################################
			# URL as an efix file
			################################
			logging.debug('epkg file NOT YET IMPLEMENTED')
		elif '.tar' in name:
			################################
			# URL as a tar file
			################################
			dst = os.path.abspath(os.path.join(os.sep, name))
			download(url, dst)
			out['epkgs_dl_ok'].append(name)
		else:
			################################
			# URL as a Directory
			################################
			context = ssl._create_unverified_context()
			response = urllib.urlopen(url, context=context)
			body = response.read()

			# find all epkg in html body
			pattern = re.compile(r'(\b[\w.]+.epkg.Z\b)')
			epkgs = list(set([epkg for epkg in pattern.findall(body)]))
			out['epkgs'].extend(epkgs)

			# download epkg
			epkgs = [epkg for epkg in epkgs if download(os.path.join(url, epkg), os.path.abspath(os.path.join(os.sep, epkg)))]
			out['epkgs_dl_ok'].extend(epkgs)

			# check prerequisite
			epkgs = [epkg for epkg in epkgs if check_prereq(os.path.abspath(os.path.join(os.sep, epkg)), 'lslpp_{}.txt'.format(machine))]
			out['epkgs_ck_ok'].extend(epkgs)
	output.update(out)

@start_threaded(thrds)
@logged
def run_installer(machine, output, epkgs):
	"""
	Install epkgs efixes
	args:
		machine (str): The remote machine name
		output	(dict): The result of the command
		epkgs	(list): The list of efixes to install
		to      (str): The directory where efixes are stored
	"""
	if epkgs:
		to = os.path.abspath(os.path.join(os.sep, 'flrtvc_lpp_source', 'emgr', 'ppc'))
		# create lpp source location
		if not os.path.exists(to): os.makedirs(to)
		# copy efix to lpp source
		for epkg in epkgs: shutil.copy(epkg, to)

		filesets = ' '.join(epkgs)
		lpp_source = 'my_lpp_source'

		try:
			# define lpp source
			if subprocess.call(args=['/usr/sbin/lsnim', '-l', lpp_source]) > 0:
				cmd = ['/usr/sbin/nim', '-o', 'define', '-t', 'lpp_source', '-a', 'server=master', '-a', 'location={}'.format(to), '-a', 'packages=all', lpp_source]
				subprocess.check_output(args=cmd, stderr=subprocess.STDOUT)

			# perform customization
			cmd = '/usr/sbin/nim -o cust -a lpp_source={} -a filesets="{}" {}'.format(lpp_source, filesets, machine)
			stdout = subprocess.check_output(args=cmd, shell=True, stderr=subprocess.STDOUT)
			logging.debug('[{}] customization result is {}'.format(__name__, stdout))
			output.update({ 'install': stdout.splitlines() })

			# remove lpp source
			cmd = ['/usr/sbin/nim', '-o', 'remove', lpp_source]
			subprocess.check_output(args=cmd, stderr=subprocess.STDOUT)

		except subprocess.CalledProcessError as e:
			logging.warn('[{}] EXCEPTION cmd={} rc={} output={}'.format(__name__, e.cmd, e.returncode, e.output))

@wait_threaded(thrds)
def wait_all():
	pass

###########################################################################################################

# Ansible module 'boilerplate'
from ansible.module_utils.basic import *

if __name__ == '__main__':
	module = AnsibleModule(
		argument_spec=dict(
			targets=dict(required=False, type='str'),
			apar=dict(required=False, choices=['sec', 'hiper', 'all', None], default=None),
			filesets=dict(required=False, type='str'),
			csv=dict(required=False, type='str'),
			path=dict(required=False, type='str'),
			verbose=dict(required=False, type='bool', default=False),
			clean=dict(required=False, type='bool', default=True),
			check_only=dict(required=False, type='bool', default=False),
			download_only=dict(required=False, type='bool', default=False),
		),
		supports_check_mode=True
	)

	# Debug
	logging.basicConfig(filename='/tmp/ansible_debug.log', format='[%(asctime)s] %(levelname)s: %(message)s', level=logging.DEBUG)
	logging.debug('*** START ***')

	# ===========================================
	# Get module params
	# ===========================================
	if module.params['targets']:
		targets = re.split('[,\s]', module.params['targets'])
	else: # empty targets
		targets = ['master']

	apar = module.params['apar']
	csvfile = module.params['csv']
	filesets = module.params['filesets']
	path = module.params['path']
	verbose = module.params['verbose']
	clean = module.params['clean']
	check_only = module.params['check_only']
	download_only = module.params['download_only']

	# metadata
	output = {}
	for m in targets: output[m] = {} # first time init
	
	# ===========================================
	# Run flrtvc script
	# ===========================================
	for m in targets: run_flrtvc(m, output[m], apar, csvfile, filesets, path, verbose)
	else: wait_all()

	if check_only: module.exit_json(changed=False, msg='exit on check only', meta=output)

	# ===========================================
	# Parse flrtvc report
	# ===========================================
	for m in targets: run_parser(m, output[m], output[m]['flrtvc_report'])
	else: wait_all()

	# ===========================================
	# Download and check efixes
	# ===========================================
	for m in targets: run_downloader(m, output[m], output[m]['extracted_urls'])
	else: wait_all()

	if download_only: module.exit_json(changed=False, msg='exit on download only', meta=output)

	# ===========================================
	# Install efixes
	# ===========================================
	for m in targets: run_installer(m, output[m], output[m]['epkgs_ck_ok'])
	else: wait_all()

	module.exit_json(changed=True, msg='exit successfully', meta=output)
