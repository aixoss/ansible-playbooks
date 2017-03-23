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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

######################################################################

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
import zipfile
import stat
# Ansible module 'boilerplate'
from ansible.module_utils.basic import *

DOCUMENTATION = """
------
module: aix_flrtvc
author: "Jerome Hurstel"
version_added: "1.0.0"
requirements: [ AIX ]
"""

# Threading
THRDS = []


def start_threaded(thds):
    """
    Decorator for thread start
    """
    def start_threaded_wrapper(func):
        """
        Decorator wrapper for thread start
        """
        def start_threaded_inner_wrapper(*args):
            """
            Decorator inner wrapper for thread start
            """
            thd = threading.Thread(target=func, args=(args))
            logging.debug('Start thread {}'.format(func.__name__))
            thd.start()
            thds.append(thd)
        return start_threaded_inner_wrapper
    return start_threaded_wrapper


def wait_threaded(thds):
    """
    Decorator for thread join
    """
    def wait_threaded_wrapper(func):
        """
        Decorator wrapper for thread join
        """
        def wait_threaded_inner_wrapper(*args):
            """
            Decorator inner wrapper for thread join
            """
            func(*args)
            for thd in thds:
                thd.join()
        return wait_threaded_inner_wrapper
    return wait_threaded_wrapper


def logged(func):
    """
    Decorator for logging
    """
    def logged_wrapper(*args):
        """
        Decorator wrapper for logging
        """
        logging.debug('ENTER {} with {}'.format(func.__name__, args))
        res = func(*args)
        logging.debug('EXIT {} with {}'.format(func.__name__, res))
        return res
    return logged_wrapper


@logged
def download(src, dst):
    """
    Download efix from url to directory
    args:
        src (str): The url to download
        dst (str): The absolute destination filename
    """
    res = True
    if not os.path.isfile(dst):
        logging.debug('downloading {} to {}...'.format(src, dst))
        try:
            cmd = ['/bin/wget', '--no-check-certificate', src, '-P', os.path.dirname(dst)]
            subprocess.check_output(args=cmd, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as exc:
            logging.warn('EXCEPTION cmd={} rc={} output={}'
                         .format(exc.cmd, exc.returncode, exc.output))
            res = False
            if exc.returncode is 3:
                increase_fs(dst)
                os.remove(dst)
                download(src, dst)
    else:
        logging.debug('{} already exists'.format(dst))
    return res


@logged
def unzip(src, dst):
    try:
        zfile = zipfile.ZipFile(src)
        zfile.extractall(dst)
    except StandardException as exc:
        logging.warn('EXCEPTION {}'.format(exc))
        increase_fs(dst)
        unzip(src, dst)


@logged
def check_prereq(epkg, ref):
    """
    Check efix prerequisites based on fileset current level
    args:
        epkg (str): The efix to check
        ref  (str): The filename with reference fileset levels
    """
    # Get fileset prerequisites
    stdout = ''
    try:
        cmd = '/usr/sbin/emgr -dXv3 -e {} | /bin/grep -p \\\"PREREQ'.format(epkg)
        stdout = subprocess.check_output(args=cmd, shell=True, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as exc:
        logging.warn('EXCEPTION cmd={} rc={} output={}'
                     .format(exc.cmd, exc.returncode, exc.output))

    res = False
    # For each prerequisites, ...
    for line in stdout.splitlines()[3:]:

        # ... skip comments and empty lines ...
        line = line.rstrip()
        if line and not line.startswith('#'):

            # ... match prerequisite ...
            match = re.match(r'^(.*?)\s+(.*?)\s+(.*?)$', line)
            if match is not None:
                (fileset, minlvl, maxlvl) = match.groups()

                # ... extract current fileset level ...
                with open(os.path.abspath(os.path.join(os.sep, ref)), 'r') as myfile:
                    for line in myfile:
                        if fileset in line:
                            curlvl = line.split(':')[2]

                            # ... and compare to min/max levels.
                            logging.debug('{} {} {} {}'.format(fileset, minlvl, curlvl, maxlvl))
                            if minlvl <= curlvl and curlvl <= maxlvl:
                                res = True
                            break
    return res


@logged
def run_lslpp(machine, filename):
    """
    Run command lslpp on a target system
    args:
        machine  (str): The remote machine name
        filename (str): The filename to store stdout
    """
    try:
        if 'master' in machine:
            cmd = ['/bin/lslpp', '-Lcq']
        else:
            cmd = ['/usr/lpp/bos.sysmgt/nim/methods/c_rsh', machine, '/bin/lslpp -Lcq']
        stdout = subprocess.check_output(args=cmd, stderr=subprocess.STDOUT)
        with open(filename, 'w') as myfile:
            myfile.write(stdout)
    except subprocess.CalledProcessError as exc:
        logging.warn('{}: EXCEPTION cmd={} rc={} output={}'
                     .format(machine, exc.cmd, exc.returncode, exc.output))


@logged
def run_emgr(machine, filename):
    """
    Run command emgr on a target system
    args:
        machine  (str): The remote machine name
        filename (str): The filename to store stdout
    """
    try:
        if 'master' in machine:
            cmd = ['/usr/sbin/emgr', '-lv3']
        else:
            cmd = ['/usr/lpp/bos.sysmgt/nim/methods/c_rsh', machine, '/usr/sbin/emgr -lv3']
        stdout = subprocess.check_output(args=cmd, stderr=subprocess.STDOUT)
        with open(filename, 'w') as myfile:
            myfile.write(stdout)
    except subprocess.CalledProcessError as exc:
        logging.warn('{}: EXCEPTION cmd={} rc={} output={}'
                     .format(machine, exc.cmd, exc.returncode, exc.output))


@start_threaded(THRDS)
@logged
def run_flrtvc(machine, output, params):
    """
    Run command flrtvc on a target system
    args:
        machine  (str): The remote machine name
        output  (dict): The result of the command
        params  (dict): The parameters to pass to flrtvc command
    """
    # Run 'lslpp -Lcq' on the remote machine and save to file
    lslpp_file = 'lslpp_{}.txt'.format(machine)
    thd1 = threading.Thread(target=run_lslpp, args=(machine, lslpp_file))
    thd1.start()

    # Run 'emgr -lv3' on the remote machine and save to file
    emgr_file = 'emgr_{}.txt'.format(machine)
    thd2 = threading.Thread(target=run_emgr, args=(machine, emgr_file))
    thd2.start()

    # Wait threads to finish
    thd1.join()
    thd2.join()

    try:
        # Prepare flrtvc command
        cmd = ['/usr/bin/flrtvc.ksh', '-e', emgr_file, '-l', lslpp_file]
        if params['apar_type'] and params['apar_type'] != 'all':
            cmd += ['-t', params['apar_type']]
        if params['apar_csv']:
            cmd += ['-f', params['apar_csv']]
        if params['filesets']:
            cmd += ['-g', params['filesets']]

        # Run flrtvc in compact mode
        logging.debug('{}: run cmd "{}"'.format(machine, ' '.join(cmd)))
        stdout_c = subprocess.check_output(args=cmd, stderr=subprocess.STDOUT)
        output.update({'0.report': stdout_c.splitlines()})

        # Save to file
        if params['dst_path']:
            if not os.path.exists(params['dst_path']):
                os.makedirs(params['dst_path'])
            filename = os.path.join(params['dst_path'], 'flrtvc_{}.txt'.format(machine))
            with open(filename, 'w') as myfile:
                if params['verbose']:
                    cmd += ['-v']
                    myfile.write(subprocess.check_output(args=cmd, stderr=subprocess.STDOUT))
                else:
                    myfile.write(stdout_c)
    except subprocess.CalledProcessError as exc:
        logging.warn('{}: EXCEPTION cmd={} rc={} output={}'
                     .format(machine, exc.cmd, exc.returncode, exc.output))
        output.update({'0.report': []})
        MODULE.exit_json(changed=CHANGED, msg='error executing flrtvc', meta=output)


@start_threaded(THRDS)
@logged
def run_parser(machine, output, report):
    """
    Parse report by extracting URLs
    args:
        machine (str): The remote machine name
        output (dict): The result of the command
        report  (str): The compact report
    """
    dict_rows = csv.DictReader(report, delimiter='|')
    pattern = re.compile(r'^(http|https|ftp)://(aix.software.ibm.com|public.dhe.ibm.com)/(aix/ifixes/.*?/|aix/efixes/security/.*?.tar)$')
    rows = [row['Download URL'] for row in dict_rows]
    rows = [row for row in rows if pattern.match(row) is not None]
    rows = list(set(rows))  # remove duplicates
    logging.debug('{}: extract {} urls in the report'.format(machine, len(rows)))
    output.update({'1.parse': rows})


@start_threaded(THRDS)
@logged
def run_downloader(machine, output, urls):
    """
    Download URLs and check efixes
    args:
        machine (str): The remote machine name
        output (dict): The result of the command
        urls   (list): The list of URLs to download
    """
    out = {'2.discover': [], '3.download': [], '4.check': []}
    for url in urls:
        protocol, srv, rep, name = re.search(r'^(.*?)://(.*?)/(.*)/(.*)$', url).groups()
        logging.debug('{}: protocol={}, srv={}, rep={}, name={}'
                      .format(machine, protocol, srv, rep, name))
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
            tar = tarfile.open(dst, 'r')

            # find all epkg in tar file
            epkgs = [epkg for epkg in tar.getnames() if re.search(r'(\b[\w.-]+.epkg.Z\b)$', epkg)]
            out['2.discover'].extend(epkgs)
            logging.debug('{}: found {} epkg.Z file in tar file'.format(machine, len(epkgs)))

            # extract epkg
            tar_dir = 'outdir'
            if not os.path.exists(tar_dir):
                os.makedirs(tar_dir)
            for epkg in epkgs:
                try:
                    tar.extract(epkg, tar_dir)
                except StandardException as exc:
                    logging.warn('EXCEPTION {}'.format(exc))
                    increase_fs(tar_dir)
                    tar.extract(epkg, tar_dir)
            epkgs = [os.path.abspath(os.path.join(os.sep, tar_dir, epkg)) for epkg in epkgs]
            out['3.download'].extend(epkgs)

            # check prerequisite
            epkgs = [epkg for epkg in epkgs if check_prereq(epkg, 'lslpp_{}.txt'.format(machine))]
            out['4.check'].extend(epkgs)
        else:
            ################################
            # URL as a Directory
            ################################
            logging.debug('{}: treat url as a directory'.format(machine))
            response = urllib.urlopen(url, context=ssl._create_unverified_context())

            # find all epkg in html body
            epkgs = [epkg for epkg in re.findall(r'(\b[\w.-]+.epkg.Z\b)', response.read())]
            epkgs = list(set(epkgs))
            out['2.discover'].extend(epkgs)
            logging.debug('{}: found {} epkg.Z file in html body'.format(machine, len(epkgs)))

            # download epkg
            epkgs = [os.path.abspath(os.path.join(os.sep, epkg)) for epkg in epkgs
                     if download(os.path.join(url, epkg), os.path.abspath(os.path.join(os.sep, epkg)))]
            out['3.download'].extend(epkgs)

            # check prerequisite
            epkgs = [epkg for epkg in epkgs if check_prereq(epkg, 'lslpp_{}.txt'.format(machine))]
            out['4.check'].extend(epkgs)
    output.update(out)


@start_threaded(THRDS)
@logged
def run_installer(machine, output, epkgs):
    """
    Install epkgs efixes
    args:
        machine (str): The remote machine name
        output (dict): The result of the command
        epkgs  (list): The list of efixes to install
    """
    global CHANGED
    if epkgs:
        destpath = os.path.abspath(os.path.join(os.sep))
        destpath = os.path.join(destpath, 'flrtvc_lpp_source', machine, 'emgr', 'ppc')
        # create lpp source location
        if not os.path.exists(destpath):
            os.makedirs(destpath)
        # copy efix destpath lpp source
        for epkg in epkgs:
            try:
                shutil.copy(epkg, destpath)
            except StandardException as exc:
                logging.warn('EXCEPTION {}'.format(exc))
                increase_fs(destpath)
                shutil.copy(epkg, destpath)
        epkgs_base = [os.path.basename(epkg) for epkg in epkgs]

        efixes = ' '.join(epkgs_base)
        lpp_source = machine + '_lpp_source'

        # define lpp source
        if subprocess.call(args=['/usr/sbin/lsnim', '-l', lpp_source]) > 0:
            try:
                cmd = '/usr/sbin/nim -o define -t lpp_source -a server=master'
                cmd += ' -a location={} -a packages=all {}'.format(destpath, lpp_source)
                subprocess.check_output(args=cmd, shell=True, stderr=subprocess.STDOUT)
            except subprocess.CalledProcessError as exc:
                logging.warn('{}: EXCEPTION cmd={} rc={} output={}'
                             .format(machine, exc.cmd, exc.returncode, exc.output))

        # perform customization
        stdout = ''
        try:
            cmd = '/usr/sbin/lsnim {}'.format(machine)
            lsnim = subprocess.check_output(args=cmd, shell=True, stderr=subprocess.STDOUT)
            nimtype = lsnim.split()[2]
            if 'master' in nimtype:
                cmd = '/usr/sbin/geninstall -d {} {}'.format(destpath, efixes)
            elif 'standalone' in nimtype:
                cmd = '/usr/sbin/nim -o cust -a lpp_source={} -a filesets="{}" {}' \
                      .format(lpp_source, efixes, machine)
            elif 'vios' in nimtype:
                cmd = '/usr/sbin/nim -o updateios -a preview=no -a lpp_source={} {}' \
                      .format(lpp_source, machine)
            stdout = subprocess.check_output(args=cmd, shell=True, stderr=subprocess.STDOUT)
            logging.debug('{}: customization result is {}'.format(machine, stdout))
            CHANGED = True
        except subprocess.CalledProcessError as exc:
            logging.warn('{}: EXCEPTION cmd={} rc={} output={}'
                         .format(machine, exc.cmd, exc.returncode, exc.output))
            stdout = exc.output
        output.update({'5.install': stdout.splitlines()})

        # remove lpp source
        if subprocess.call(args=['/usr/sbin/lsnim', '-l', lpp_source]) == 0:
            try:
                cmd = '/usr/sbin/nim -o remove {}'.format(lpp_source)
                subprocess.check_output(args=cmd, shell=True, stderr=subprocess.STDOUT)
            except subprocess.CalledProcessError as exc:
                logging.warn('{}: EXCEPTION cmd={} rc={} output={}'
                             .format(machine, exc.cmd, exc.returncode, exc.output))


@wait_threaded(THRDS)
def wait_all():
    """
    Do nothing
    """
    pass


def client_list():
    """
    Build client list (standalone and vios)
    """
    stdout = ''
    try:
        cmd = ['lsnim', '-t', 'standalone']
        stdout = subprocess.check_output(args=cmd, stderr=subprocess.STDOUT)
        cmd = ['lsnim', '-t', 'vios']
        stdout += subprocess.check_output(args=cmd, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as exc:
        logging.warn('EXCEPTION cmd={} rc={} output={}'
                     .format(exc.cmd, exc.returncode, exc.output))
    nim_clients = [line.split()[0] for line in stdout.splitlines()]
    nim_clients.append('master')
    return nim_clients


def expand_targets(targets, nim_clients):
    """
    Expand wildcard in target list
    """
    for machine in targets:
        if '*' in machine:
            # replace wildcard character by corresponding machines
            i = targets.index(machine)
            pattern = r'.*?\b(?![\w-])'
            targets[i:i+1] = re.findall(machine.replace('*', pattern), ' '.join(nim_clients))
    logging.debug(targets)
    return targets


def increase_fs(dest):
    """
    Increase filesystem by 100Mb
    """
    try:
        cmd = ['df', '-c', dest]
        stdout = subprocess.check_output(args=cmd, stderr=subprocess.STDOUT)
        mount_point = stdout.splitlines()[1].split(':')[6]
        cmd = ['chfs', '-a', 'size=+100M', mount_point]
        stdout = subprocess.check_output(args=cmd, stderr=subprocess.STDOUT)
        logging.debug('{}: {}'.format(mount_point, stdout))
    except subprocess.CalledProcessError as exc:
        logging.warn('EXCEPTION cmd={} rc={} output={}'
                     .format(exc.cmd, exc.returncode, exc.output))


###################################################################################################


if __name__ == '__main__':
    MODULE = AnsibleModule(
        argument_spec=dict(
            targets=dict(required=True, type='str'),
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

    CHANGED = False

    # Logging
    LOGNAME = '/tmp/ansible_debug.log'
    LOGFRMT = '[%(asctime)s] %(levelname)s: [%(funcName)s:%(thread)d] %(message)s'
    logging.basicConfig(filename=LOGNAME, format=LOGFRMT, level=logging.DEBUG)
    logging.debug('*** START ***')

    # ===========================================
    # Get client list
    # ===========================================
    logging.debug('*** OHAI ***')
    NIM_CLIENTS = client_list()
    logging.debug(NIM_CLIENTS)

    # ===========================================
    # Get module params
    # ===========================================
    logging.debug('*** INIT ***')
    TARGETS = expand_targets(re.split(r'[,\s]', MODULE.params['targets']), NIM_CLIENTS)
    FLRTVC_PARAMS = {'apar_type': MODULE.params['apar'],
                     'apar_csv':  MODULE.params['csv'],
                     'filesets':  MODULE.params['filesets'],
                     'dst_path':  MODULE.params['path'],
                     'verbose':   MODULE.params['verbose']}
    CLEAN = MODULE.params['clean']
    CHECK_ONLY = MODULE.params['check_only']
    DOWNLOAD_ONLY = MODULE.params['download_only']

    # metadata
    OUTPUT = {}
    for MACHINE in TARGETS:
        OUTPUT[MACHINE] = {}  # first time init

    # ===========================================
    # Install flrtvc script
    # ===========================================
    logging.debug('*** INSTALL ***')
    flrtvcpath = os.path.abspath(os.path.join(os.sep, 'usr', 'bin'))
    flrtvcfile = os.path.join(flrtvcpath, 'flrtvc.ksh')
    if not os.path.exists(flrtvcfile):
        destname = os.path.abspath(os.path.join(os.sep, 'FLRTVC-latest.zip'))
        download('https://www-304.ibm.com/webapp/set2/sas/f/flrt3/FLRTVC-latest.zip', destname)
        unzip(destname, os.path.abspath(os.path.join(os.sep, 'usr', 'bin')))
    st = os.stat(flrtvcfile)
    if not st.st_mode & stat.S_IEXEC:
        os.chmod(flrtvcfile, st.st_mode | stat.S_IEXEC)

    # ===========================================
    # Run flrtvc script
    # ===========================================
    logging.debug('*** REPORT ***')
    for MACHINE in TARGETS:
        run_flrtvc(MACHINE, OUTPUT[MACHINE], FLRTVC_PARAMS)
    wait_all()

    if CHECK_ONLY:
        MODULE.exit_json(changed=CHANGED, msg='exit on check only', meta=OUTPUT)

    # ===========================================
    # Parse flrtvc report
    # ===========================================
    logging.debug('*** PARSE ***')
    for MACHINE in TARGETS:
        run_parser(MACHINE, OUTPUT[MACHINE], OUTPUT[MACHINE]['0.report'])
    wait_all()

    # ===========================================
    # Download and check efixes
    # ===========================================
    logging.debug('*** DOWNLOAD ***')
    for MACHINE in TARGETS:
        run_downloader(MACHINE, OUTPUT[MACHINE], OUTPUT[MACHINE]['1.parse'])
    wait_all()

    if DOWNLOAD_ONLY:
        MODULE.exit_json(changed=CHANGED, msg='exit on download only', meta=OUTPUT)

    # ===========================================
    # Install efixes
    # ===========================================
    logging.debug('*** UPDATE ***')
    for MACHINE in TARGETS:
        run_installer(MACHINE, OUTPUT[MACHINE], OUTPUT[MACHINE]['4.check'])
    wait_all()

    MODULE.exit_json(changed=CHANGED, msg='exit successfully', meta=OUTPUT)
