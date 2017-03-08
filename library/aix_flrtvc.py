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
import tarfile

thrds = []

def start_threaded(thrds):
	def start_threaded_wrapper(func):
		def start_threaded_inner_wrapper(*args, **kwargs):
			p = threading.Thread(target=func, args=(args))
			logging.debug('Start thread {}'.format(func.__name__))
			p.start()
			thrds.append(p)
		return start_threaded_inner_wrapper
	return start_threaded_wrapper

def wait_threaded(thrds):
	def wait_threaded_wrapper(func):
		def wait_threaded_inner_wrapper(*args, **kwargs):
			[p.join() for p in thrds]
		return wait_threaded_inner_wrapper
	return wait_threaded_wrapper

def logged(func):
	def logged_wrapper(*args, **kwargs):
		logging.debug('ENTER {} with {}'.format(func.__name__, args))
		res = func(*args, **kwargs)
		logging.debug('EXIT {} with {}'.format(func.__name__, res))
		return res
	return logged_wrapper

@logged
def download(src, dst):
	"""
	Download efix from url to directory
	args:
		src (str): The url to download
		dst	(str): The absolute destination filename
	"""
	res = True
	if not os.path.isfile(dst):
		logging.debug('downloading {} to {}...'.format(src, dst))
		try:
			subprocess.check_output(args=['/bin/wget', '--no-check-certificate', src, '-P', os.path.dirname(dst)], stderr=subprocess.STDOUT)
		except subprocess.CalledProcessError as e:
			logging.warn('EXCEPTION cmd={} rc={} output={}'.format(e.cmd, e.returncode, e.output))
			#if e.returncode == 3:
			#	subprocess.call(args=['/usr/sbin/chfs', '-a size=+100M', os.path.dirname(dst)])
				
			res = False
	else:
		logging.debug('{} already exists'.format(dst))
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

@logged
def check_prereq(epkg, ref):
	"""
	Check efix prerequisites based on fileset current level
	args:
		epkg (str): The efix to check
		ref	 (str): The filename with reference fileset levels
	"""
	# Get fileset prerequisites
	stdout = ''
	try:
		cmd = '/usr/sbin/emgr -dXv3 -e {} | /bin/grep -p \\\"PREREQ'.format(epkg)
		stdout = subprocess.check_output(args=cmd, shell=True, stderr=subprocess.STDOUT)
	except subprocess.CalledProcessError as e:
		logging.warn('EXCEPTION cmd={} rc={} output={}'.format(e.cmd, e.returncode, e.output))

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
		if 'master' in machine:
			cmd = ['/bin/lslpp', '-Lcq']
		else:
			cmd = ['/usr/lpp/bos.sysmgt/nim/methods/c_rsh', machine, '/bin/lslpp -Lcq']
		stdout = subprocess.check_output(args=cmd, stderr=subprocess.STDOUT)
		with open(file,'w') as f: f.write(stdout)
	except subprocess.CalledProcessError as e:
		logging.warn('{}: EXCEPTION cmd={} rc={} output={}'.format(machine, e.cmd, e.returncode, e.output))

@logged
def run_emgr(machine, file):
	"""
	Run command emgr on a target system
	args:
		machine (str): The remote machine name
		file	(str): The filename to store stdout
	"""
	try:
		if 'master' in machine:
			cmd = ['/usr/sbin/emgr', '-lv3']
		else:
			cmd = ['/usr/lpp/bos.sysmgt/nim/methods/c_rsh', machine, '/usr/sbin/emgr -lv3']
		stdout = subprocess.check_output(args=cmd, stderr=subprocess.STDOUT)
		with open(file,'w') as f: f.write(stdout)
	except subprocess.CalledProcessError as e:
		logging.warn('{}: EXCEPTION cmd={} rc={} output={}'.format(machine, e.cmd, e.returncode, e.output))

@start_threaded(thrds)
@logged
def run_flrtvc(machine, output, apar, csv, filesets, path, verbose):
	"""
	Run command flrtvc on a target system
	args:
		machine (str): The remote machine name
		output	(dict): The result of the command
		apar	(str): 
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

	try:
		# Prepare flrtvc command
		cmd = ['/usr/bin/flrtvc.ksh', '-e', emgr_file, '-l', lslpp_file]
		if apar and apar != 'all': cmd += ['-t', apar]
		if csv:	cmd += ['-f', csv]
		if filesets: cmd += ['-g', filesets]

		# Run flrtvc in compact and verbose mode
		stdout_c = subprocess.check_output(args=cmd, stderr=subprocess.STDOUT)
		stdout_v = subprocess.check_output(args=cmd+['-v'], stderr=subprocess.STDOUT)

		# Save to variable ('0.report' value is used in run_parser func)
		output.update({ '0.report': stdout_c.splitlines() })

		# Save to file
		if path:
			stdout = stdout_c
			if verbose: stdout = stdout_v
			if not os.path.exists(path): os.makedirs(path)
			with open(os.path.join(path, 'flrtvc_{}.txt'.format(machine)),'w') as f: f.write(stdout)
	except subprocess.CalledProcessError as e:
		logging.warn('{}: EXCEPTION cmd={} rc={} output={}'.format(machine, e.cmd, e.returncode, e.output))
		output.update({ '0.report': [] })
		module.exit_json(changed=False, msg='error executing flrtvc', meta=output)

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
	output.update({ '1.parse': rows })

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
	out = { '2.discover': [], '3.download': [], '4.check': [] }
	for url in urls:
		protocol, srv, dir, name = re.search(r'^(.*?)://(.*?)/(.*)/(.*)$', url).groups()
		logging.debug('{}: protocol={}, srv={}, dir={}, name={}'.format(machine, protocol, srv, dir, name))
		if '.epkg.Z' in name:
			################################
			# URL as an efix file
			################################
			logging.debug('{}: treat url as an epkg file'.format(machine))
			out['2.discover'].extend(name)

			# download epkg file
			epkg = os.path.abspath(os.path.join(os.sep, name))
			if download(url, epkg):
				out['3.download'].extend(epkg)

			# check prerequisite
			if check_prereq(epkg, 'lslpp_{}.txt'.format(machine)):
				out['4.check'].extend(epkg)

		elif '.tar' in name:
			################################
			# URL as a tar file
			################################
			logging.debug('{}: treat url as a tar file'.format(machine))
			dst = os.path.abspath(os.path.join(os.sep, name))

			# download and open tar file
			download(url, dst)
			t = tarfile.open(dst, 'r')

			# find all epkg in tar file
			pattern = re.compile(r'(\b[\w.-]+.epkg.Z\b)$')
			epkgs = [epkg for epkg in t.getnames() if pattern.search(epkg)]
			out['2.discover'].extend(epkgs)
			logging.debug('{}: found {} epkg.Z file in tar file'.format(machine, len(epkgs)))

			# extract epkg
			tar_dir = 'outdir'
			if not os.path.exists(tar_dir): os.makedirs(tar_dir)
			for epkg in epkgs:
				t.extract(epkg, tar_dir)
			epkgs = [os.path.abspath(os.path.join(os.sep, tar_dir, epkg)) for epkg in epkgs]
			out['3.download'].extend(epkgs)

			# check prerequisite
			epkgs = [epkg for epkg in epkgs if check_prereq(epkg, 'lslpp_{}.txt'.format(machine))]
			out['4.check'].extend(epkgs)
		else:
			################################
			# URL as a Directory
			################################
			context = ssl._create_unverified_context()
			response = urllib.urlopen(url, context=context)
			body = response.read()
			logging.debug('{}: treat url as a directory'.format(machine))

			# find all epkg in html body
			pattern = re.compile(r'(\b[\w.-]+.epkg.Z\b)')
			epkgs = list(set([epkg for epkg in pattern.findall(body)]))
			out['2.discover'].extend(epkgs)
			logging.debug('{}: found {} epkg.Z file in html body'.format(machine, len(epkgs)))

			# download epkg
			epkgs = [os.path.abspath(os.path.join(os.sep, epkg)) for epkg in epkgs if download(os.path.join(url, epkg), os.path.abspath(os.path.join(os.sep, epkg)))]
			out['3.download'].extend(epkgs)

			# check prerequisite
			epkgs = [epkg for epkg in epkgs if check_prereq(epkg, 'lslpp_{}.txt'.format(machine))]
			out['4.check'].extend(epkgs)
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
		to		(str): The directory where efixes are stored
	"""
	if epkgs:
		to = os.path.abspath(os.path.join(os.sep, 'flrtvc_lpp_source', machine, 'emgr', 'ppc'))
		# create lpp source location
		if not os.path.exists(to): os.makedirs(to)
		# copy efix to lpp source
		for epkg in epkgs: shutil.copy(epkg, to)
		epkgs_base = [os.path.basename(epkg) for epkg in epkgs]

		filesets = ' '.join(epkgs_base)
		lpp_source = machine + '_lpp_source'

		# define lpp source
		if subprocess.call(args=['/usr/sbin/lsnim', '-l', lpp_source]) > 0:
			try:
				cmd = ['/usr/sbin/nim', '-o', 'define', '-t', 'lpp_source', '-a', 'server=master', '-a', 'location={}'.format(to), '-a', 'packages=all', lpp_source]
				subprocess.check_output(args=cmd, stderr=subprocess.STDOUT)
			except subprocess.CalledProcessError as e:
				logging.warn('{}: EXCEPTION cmd={} rc={} output={}'.format(machine, e.cmd, e.returncode, e.output))

		# perform customization
		stdout = ''
		try:
			type = subprocess.check_output(args=['/usr/sbin/lsnim', machine], stderr=subprocess.STDOUT).split()[2]
			if 'master' in type:
				cmd = '/usr/sbin/geninstall -d {} {}'.format(to, filesets)
			elif 'standalone' in type:
				cmd = '/usr/sbin/nim -o cust -a lpp_source={} -a filesets="{}" {}'.format(lpp_source, filesets, machine)
			elif 'vios' in type:
				cmd = '/usr/sbin/nim -o updateios -a preview=no -a lpp_source={} {}'.format(lpp_source, machine)
			stdout = subprocess.check_output(args=cmd, shell=True, stderr=subprocess.STDOUT)
			logging.debug('{}: customization result is {}'.format(machine, stdout))
		except subprocess.CalledProcessError as e:
			logging.warn('{}: EXCEPTION cmd={} rc={} output={}'.format(machine, e.cmd, e.returncode, e.output))
			stdout = e.output
		output.update({ '5.install': stdout.splitlines() })

		# remove lpp source
		if subprocess.call(args=['/usr/sbin/lsnim', '-l', lpp_source]) == 0:
			try:
				cmd = ['/usr/sbin/nim', '-o', 'remove', lpp_source]
				subprocess.check_output(args=cmd, stderr=subprocess.STDOUT)
			except subprocess.CalledProcessError as e:
				logging.warn('{}: EXCEPTION cmd={} rc={} output={}'.format(machine, e.cmd, e.returncode, e.output))

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
	logging.basicConfig(filename='/tmp/ansible_debug.log', format='[%(asctime)s] %(levelname)s: [%(funcName)s:%(thread)d] %(message)s', level=logging.DEBUG)
	logging.debug('*** START ***')

	# ===========================================
	# Get client list
	# ===========================================
	logging.debug('*** OHAI ***')
	stdout = ''
	try:
		cmd = ['lsnim', '-t', 'standalone']
		stdout = subprocess.check_output(args=cmd, stderr=subprocess.STDOUT)
		cmd = ['lsnim', '-t', 'vios']
		stdout += subprocess.check_output(args=cmd, stderr=subprocess.STDOUT)
	except subprocess.CalledProcessError as e:
		logging.warn('EXCEPTION cmd={} rc={} output={}'.format(e.cmd, e.returncode, e.output))
	nim_clients = [line.split()[0] for line in stdout.splitlines()]
	nim_clients.append('master')
	logging.debug(nim_clients)

	# ===========================================
	# Get module params
	# ===========================================
	logging.debug('*** INIT ***')
	if module.params['targets']:
		targets = re.split(r'[,\s]', module.params['targets'])
		for m in targets:
			if '*' in m:
				# replace wildcard character by corresponding machines
				i = targets.index(m)
				targets[i:i+1] = re.findall(m.replace('*', r'.*?\b(?![\w-])'), ' '.join(nim_clients))
		logging.debug(targets)
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
	logging.debug('*** REPORT ***')
	for m in targets: run_flrtvc(m, output[m], apar, csvfile, filesets, path, verbose)
	else: wait_all()

	if check_only: module.exit_json(changed=False, msg='exit on check only', meta=output)

	# ===========================================
	# Parse flrtvc report
	# ===========================================
	logging.debug('*** PARSE ***')
	for m in targets: run_parser(m, output[m], output[m]['0.report'])
	else: wait_all()

	# ===========================================
	# Download and check efixes
	# ===========================================
	logging.debug('*** DOWNLOAD ***')
	for m in targets: run_downloader(m, output[m], output[m]['1.parse'])
	else: wait_all()

	if download_only: module.exit_json(changed=False, msg='exit on download only', meta=output)

	# ===========================================
	# Install efixes
	# ===========================================
	logging.debug('*** UPDATE ***')
	for m in targets: run_installer(m, output[m], output[m]['4.check'])
	else: wait_all()

	module.exit_json(changed=True, msg='exit successfully', meta=output)
