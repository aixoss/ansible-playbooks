#!/usr/bin/python
#
# Copyright 2016, International Business Machines Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

######################################################################
"""AIX FLRTVC: generate flrtvc report, download and install efix"""

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
# pylint: disable=wildcard-import,unused-wildcard-import
from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = """
------
module: aix_flrtvc
author: "Jerome Hurstel, Alain Poncet, Vianney Robin"
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
            logging.warning('EXCEPTION cmd={} rc={} output={}'
                            .format(exc.cmd, exc.returncode, exc.output))
            res = False
            if exc.returncode == 3:
                increase_fs(dst)
                os.remove(dst)
                download(src, dst)
    else:
        logging.debug('{} already exists'.format(dst))
    return res


@logged
def unzip(src, dst):
    """
    Unzip source into the destination directory
        - src (str): The url to unzip
        - dst (str): The absolute destination path
    """
    try:
        zfile = zipfile.ZipFile(src)
        zfile.extractall(dst)
    except (zipfile.BadZipfile, zipfile.LargeZipFile, RuntimeError) as exc:
        logging.warning('EXCEPTION {}'.format(exc))
        increase_fs(dst)
        unzip(src, dst)


@logged
def locked_fileset(machine, fileset):
    """
    Check if a fileset is locked
        - machine (str): The target machine
        - fileset (str): Fileset to check
    """
    try:
        cmd = ['/usr/lpp/bos.sysmgt/nim/methods/c_rsh', machine, ' {}'.format(fileset)]
        logging.debug(' '.join(cmd))
        stdout = subprocess.check_output(args=cmd, stderr=subprocess.STDOUT)
        logging.debug('{}: command result is {}'.format(machine, stdout))
    except subprocess.CalledProcessError as exc:
        logging.warning('{}: EXCEPTION cmd={} rc={} output={}'
                        .format(machine, exc.cmd, exc.returncode, exc.output))
        stdout = exc.output


@logged
def remove_efix(machine, label):
    """
    Remove Efix with the given label on the machine
        - machine (str): The target machine
        - label   (str): Efix name to remove
    """
    try:
        cmd = ['/usr/lpp/bos.sysmgt/nim/methods/c_rsh', machine,
               '/usr/sbin/emgr -r -L {}'.format(label)]
        logging.debug(' '.join(cmd))
        stdout = subprocess.check_output(args=cmd, stderr=subprocess.STDOUT)
        logging.debug('{}: command result is {}'.format(machine, stdout))
    except subprocess.CalledProcessError as exc:
        logging.warning('{}: EXCEPTION cmd={} rc={} output={}'
                        .format(machine, exc.cmd, exc.returncode, exc.output))
        stdout = exc.output


@logged
def check_prereq(epkg, ref, machine, force):
    """
    Check efix prerequisites based on fileset current level
    args:
        epkg    (str) : The efix to check
        ref     (str) : The filename with reference fileset levels
        machine (str) : The target machine
        force   (bool): The flag to automatically remove efixes
    """
    # Get fileset prerequisites
    stdout = ''
    try:
        cmd = '/usr/sbin/emgr -dXv3 -e {} | /bin/grep -p \\\"PREREQ'.format(epkg)
        stdout = subprocess.check_output(args=cmd, shell=True, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as exc:
        logging.warning('EXCEPTION cmd={} rc={} output={}'
                        .format(exc.cmd, exc.returncode, exc.output))

    res = True
    # For each prerequisites, ...
    for line in stdout.splitlines()[3:]:

        # ... skip comments and empty lines ...
        line = line.rstrip()
        if line and not line.startswith('#'):

            # ... match prerequisite ...
            match = re.match(r'^(.*?)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+).*?$', line)
            if match is not None:
                (fileset, minlvl, maxlvl) = match.groups()
                minlvl_i = list(map(int, minlvl.split(".")))
                maxlvl_i = list(map(int, maxlvl.split(".")))

                # ... check if fileset is locked ...
#                if locked_fileset(machine, ref):
#                    if force:
#                        # ... automatically remove efixes
#                        remove_efix(machine, label)
#                    else:
#                        # ... reject fileset from list
#                        break

                # ... extract current fileset level ...
                with open(os.path.abspath(os.path.join(os.sep, ref)), 'r') as myfile:
                    found = False
                    for myline in myfile:
                        if fileset in myline:
                            found = True
                            curlvl = myline.split(':')[2]
                            curlvl_i = list(map(int, curlvl.split(".")))

                            # ... and compare to min/max levels.
                            logging.debug('{} {} {} {}'.format(fileset, minlvl, curlvl, maxlvl))
                            if curlvl_i < minlvl_i or curlvl_i > maxlvl_i:
                                res = False
                            break

                    if found is False:
                        res = False

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
        logging.error('{}: EXCEPTION cmd={} rc={} output={}'
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
        logging.error('{}: EXCEPTION cmd={} rc={} output={}'
                      .format(machine, exc.cmd, exc.returncode, exc.output))


# @start_threaded(THRDS)
@logged
def run_flrtvc(machine, output, params):
    """
    Run command flrtvc on a target system
    args:
        machine  (str): The remote machine name
        output  (dict): The result of the command
        params  (dict): The parameters to pass to flrtvc command
    """

    global WORKDIR

    # Run 'lslpp -Lcq' on the remote machine and save to file
    lslpp_file = os.path.join(WORKDIR, 'lslpp_{}.txt'.format(machine))
    if os.path.exists(lslpp_file):
        os.remove(lslpp_file)
    thd1 = threading.Thread(target=run_lslpp, args=(machine, lslpp_file))
    thd1.start()

    # Run 'emgr -lv3' on the remote machine and save to file
    emgr_file = os.path.join(WORKDIR, 'emgr_{}.txt'.format(machine))
    if os.path.exists(emgr_file):
        os.remove(emgr_file)
    thd2 = threading.Thread(target=run_emgr, args=(machine, emgr_file))
    thd2.start()

    # Wait threads to finish
    thd1.join()
    thd2.join()

    if not os.path.exists(lslpp_file) or not os.path.exists(emgr_file):
        if not os.path.exists(lslpp_file):
            output.update({'0.report': 'Failed to list filsets (lslpp) on {}, {} does not exist.'
                                       .format(machine, lslpp_file)})
        if not os.path.exists(emgr_file):
            output.update({'0.report': 'Failed to list fixes (emgr) on {}, {} does not exist.'
                                       .format(machine, emgr_file)})
        return 1

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
        logging.warning('{}: EXCEPTION cmd={} rc={} output={}'
                        .format(machine, exc.cmd, exc.returncode, exc.output))
        output.update({'0.report': []})
        MODULE.exit_json(changed=CHANGED, msg='error executing flrtvc', meta=output)
    return 0


# @start_threaded(THRDS)
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
    pattern = re.compile(r'^(http|https|ftp)://(aix.software.ibm.com|public.dhe.ibm.com)'
                         r'/(aix/ifixes/.*?/|aix/efixes/security/.*?.tar)$')
    rows = [row['Download URL'] for row in dict_rows]
    rows = [row for row in rows if pattern.match(row) is not None]
    rows = list(set(rows))  # remove duplicates
    logging.debug('{}: extract {} urls in the report'.format(machine, len(rows)))
    output.update({'1.parse': rows})


# @start_threaded(THRDS)
@logged
def run_downloader(machine, output, urls, force):
    """
    Download URLs and check efixes
    args:
        machine (str): The remote machine name
        output (dict): The result of the command
        urls   (list): The list of URLs to download
    """

    global WORKDIR

    out = {'2.discover': [], '3.download': [], '4.check': []}
    lslpp_file = os.path.join(WORKDIR, 'lslpp_{}.txt'.format(machine))
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
            epkg = os.path.abspath(os.path.join(WORKDIR, name))
            if download(url, epkg):
                out['3.download'].extend(epkg)

            # check prerequisite
            if check_prereq(epkg, lslpp_file, machine, force):
                out['4.check'].extend(epkg)

        elif '.tar' in name:
            ################################
            # URL as a tar file
            ################################
            logging.debug('{}: treat url as a tar file'.format(machine))
            dst = os.path.abspath(os.path.join(WORKDIR, name))

            # download and open tar file
            download(url, dst)
            tar = tarfile.open(dst, 'r')

            # find all epkg in tar file
            epkgs = [epkg for epkg in tar.getnames() if re.search(r'(\b[\w.-]+.epkg.Z\b)$', epkg)]
            out['2.discover'].extend(epkgs)
            logging.debug('{}: found {} epkg.Z file in tar file'.format(machine, len(epkgs)))

            # extract epkg
            tar_dir = os.path.join(WORKDIR, 'tardir')
            if not os.path.exists(tar_dir):
                os.makedirs(tar_dir)
            for epkg in epkgs:
                try:
                    tar.extract(epkg, tar_dir)
                except (OSError, IOError, tarfile.TarError) as exc:
                    logging.warning('EXCEPTION {}'.format(exc))
                    increase_fs(tar_dir)
                    tar.extract(epkg, tar_dir)
            epkgs = [os.path.abspath(os.path.join(tar_dir, epkg)) for epkg in epkgs]
            out['3.download'].extend(epkgs)

            # check prerequisite
            epkgs = [epkg for epkg in epkgs if check_prereq(epkg, lslpp_file, machine, force)]
            out['4.check'].extend(epkgs)
        else:
            ################################
            # URL as a Directory
            ################################
            logging.debug('{}: treat url as a directory'.format(machine))
            # pylint: disable=protected-access
            response = urllib.urlopen(url, context=ssl._create_unverified_context())

            # find all epkg in html body
            epkgs = [epkg for epkg in re.findall(r'(\b[\w.-]+.epkg.Z\b)', response.read())]
            epkgs = list(set(epkgs))
            out['2.discover'].extend(epkgs)
            logging.debug('{}: found {} epkg.Z file in html body'.format(machine, len(epkgs)))

            # download epkg
            epkgs = [os.path.abspath(os.path.join(WORKDIR, epkg)) for epkg in epkgs
                     if download(os.path.join(url, epkg),
                                 os.path.abspath(os.path.join(WORKDIR, epkg)))]
            out['3.download'].extend(epkgs)

            # check prerequisite
            epkgs = [epkg for epkg in epkgs if check_prereq(epkg, lslpp_file, machine, force)]
            out['4.check'].extend(epkgs)
    output.update(out)


@start_threaded(THRDS)
@logged
def run_installer(machine, output, epkgs, force):
    """
    Install epkgs efixes
    args:
        machine (str): The remote machine name
        output (dict): The result of the command
        epkgs  (list): The list of efixes to install
    """

    global CHANGED
    global WORKDIR

    if epkgs:
        destpath = os.path.abspath(os.path.join(WORKDIR))
        destpath = os.path.join(destpath, 'flrtvc_lpp_source', machine, 'emgr', 'ppc')
        # create lpp source location
        if not os.path.exists(destpath):
            os.makedirs(destpath)
        # copy efix destpath lpp source
        for epkg in epkgs:
            try:
                shutil.copy(epkg, destpath)
            except (IOError, shutil.Error) as exc:
                logging.warning('EXCEPTION {}'.format(exc))
                increase_fs(destpath)
                shutil.copy(epkg, destpath)
        epkgs_base = [os.path.basename(epkg) for epkg in epkgs]
        epkgs_base.sort(reverse=True)

        efixes = ' '.join(epkgs_base)
        lpp_source = machine + '_lpp_source'

        # define lpp source
        if subprocess.call(args=['/usr/sbin/lsnim', '-l', lpp_source]) > 0:
            try:
                cmd = '/usr/sbin/nim -o define -t lpp_source -a server=master'
                cmd += ' -a location={} -a packages=all {}'.format(destpath, lpp_source)
                subprocess.check_output(args=cmd, shell=True, stderr=subprocess.STDOUT)
            except subprocess.CalledProcessError as exc:
                logging.warning('{}: EXCEPTION cmd={} rc={} output={}'
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
            logging.warning('{}: EXCEPTION cmd={} rc={} output={}'
                            .format(machine, exc.cmd, exc.returncode, exc.output))
            stdout = exc.output
        output.update({'5.install': stdout.splitlines()})

        # remove lpp source
        if subprocess.call(args=['/usr/sbin/lsnim', '-l', lpp_source]) == 0:
            try:
                cmd = '/usr/sbin/nim -o remove {}'.format(lpp_source)
                subprocess.check_output(args=cmd, shell=True, stderr=subprocess.STDOUT)
            except subprocess.CalledProcessError as exc:
                logging.warning('{}: EXCEPTION cmd={} rc={} output={}'
                                .format(machine, exc.cmd, exc.returncode, exc.output))


@wait_threaded(THRDS)
def wait_all():
    """
    Do nothing
    """
    pass


def parse_nim_info(output):
    """
    Build client nim info dictionary from output of lsnim command.
    """
    obj_key = ''


def client_list():
    """
    Build client list (standalone and vios)
    """
    stdout = ''
    info = {}
    try:
        cmd = ['lsnim', '-c', 'machines', '-l']
        stdout = subprocess.check_output(args=cmd, stderr=subprocess.STDOUT)
        # cmd = ['lsnim', '-t', 'vios', '-l']
        # stdout2 = subprocess.check_output(args=cmd, stderr=subprocess.STDOUT)
        # stdout = stdout + "\n" + stdout2
    except subprocess.CalledProcessError as exc:
        logging.warning('EXCEPTION cmd={} rc={} output={}'
                        .format(exc.cmd, exc.returncode, exc.output))
        return info

    for line in stdout.split('\n'):
        line = line.rstrip()
        match_key = re.match(r"^(\S+):", line)
        if match_key:
            obj_key = match_key.group(1)
            info[obj_key] = {}
            continue
        rmatch_attr = re.match(r"^\s+(\S+)\s+=\s+(.*)$", line)
        if rmatch_attr:
            info[obj_key][rmatch_attr.group(1)] = rmatch_attr.group(2)
            continue
    info['master'] = {}

    return info


def expand_targets(targets_list, nim_clients):
    """
    Expand the list of the targets.

    a taget name could be of the following form:
        target*       all the nim client machines whose name starts
                          with 'target'
        target[n1:n2] where n1 and n2 are numeric: target<n1> to target<n2>
        * or ALL      all the nim client machines
        client_name   the nim client named 'client_name'
        master        the nim master

        sample:  target[1:5] target12 other_target*

    arguments:
        machine (str): The name machine
        result  (dict): The result of the command

    return: the list of the existing machines matching the target list
    """
    clients = []

    for target in targets_list:

        # -----------------------------------------------------------
        # Build target(s) from: range i.e. quimby[7:12]
        # -----------------------------------------------------------
        rmatch = re.match(r"(\w+)\[(\d+):(\d+)\]", target)
        if rmatch:

            name = rmatch.group(1)
            start = rmatch.group(2)
            end = rmatch.group(3)

            for i in range(int(start), int(end) + 1):
                # target_results.append('{0}{1:02}'.format(name, i))
                curr_name = name + str(i)
                if curr_name in nim_clients:
                    clients.append(curr_name)

            continue

        # -----------------------------------------------------------
        # Build target(s) from: val*. i.e. quimby*
        # -----------------------------------------------------------
        rmatch = re.match(r"(\w+)\*$", target)
        if rmatch:

            name = rmatch.group(1)

            for curr_name in nim_clients:
                if re.match(r"^%s\.*" % name, curr_name):
                    clients.append(curr_name)

            continue

        # -----------------------------------------------------------
        # Build target(s) from: all or *
        # -----------------------------------------------------------
        if target.upper() == 'ALL' or target == '*':
            clients = nim_clients
            continue

        # -----------------------------------------------------------
        # Build target(s) from: quimby05 quimby08 quimby12
        # -----------------------------------------------------------
        if (target in nim_clients) or (target == 'master'):
            clients.append(target)

    return list(set(clients))


def check_targets(targets_list, nim_clients, output):
    """
    Check if each target in the target list can be reached.
    Build a new target list with reachable target only.

    arguments:
        targets_list (str): list of existing machines
        nim_clients (dict): nim info of all clients
        output      (dict): The result of the command

    """
    targets = []

    for machine in targets_list:
        if machine == 'master':
            targets.append(machine)
            continue

        if nim_clients[machine]['Cstate'] != 'ready for a NIM operation':
            logging.warning('Machine: {} is not ready for NIM operation'.format(machine))
            continue

        try:
            cmd = ['/usr/lpp/bos.sysmgt/nim/methods/c_rsh', machine, '/usr/bin/ls']
            ret = subprocess.call(args=cmd, stderr=subprocess.STDOUT)
            if ret == 0:
                targets.append(machine)
            else:
                logging.warning('Cannot reach {} with c_rsh: rc={}'.format(machine, ret))
                output[machine].update({'0.report': 'Cannot reach {} with c_rsh: rc={}'
                                                    .format(machine, ret)})
        except subprocess.CalledProcessError as exc:
            logging.warning('Cannot reach {} with c_rsh: rc={} output={}'
                            .format(machine, exc.returncode, exc.output))
            output[machine].update({'0.report': 'Cannot reach {}, {} failed: {}'
                                                .format(machine, exc.cmd, exc.output)})
            continue

    return list(set(targets))


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
        logging.warning('EXCEPTION cmd={} rc={} output={}'
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
            force=dict(required=False, type='bool', default=False),
            clean=dict(required=False, type='bool', default=True),
            check_only=dict(required=False, type='bool', default=False),
            download_only=dict(required=False, type='bool', default=False),
        ),
        supports_check_mode=True
    )

    CHANGED = False

    # Logging
    LOGNAME = '/tmp/ansible_flrtvc_debug.log'
    LOGFRMT = '[%(asctime)s] %(levelname)s: [%(funcName)s:%(thread)d] %(message)s'
    logging.basicConfig(filename=LOGNAME, format=LOGFRMT, level=logging.DEBUG)

    logging.debug('*** START ***')

    # ===========================================
    # Get client list
    # ===========================================
    logging.debug('*** OHAI ***')
    NIM_CLIENTS = client_list()
    logging.debug('Nim clients are: {}'.format(NIM_CLIENTS))

    # ===========================================
    # Get module params
    # ===========================================
    logging.debug('*** INIT ***')
    logging.debug('required targets are:{}'.format(MODULE.params['targets']))
    TARGETS = expand_targets(re.split(r'[,\s]', MODULE.params['targets']), NIM_CLIENTS.keys())
    logging.debug('Nim client targets are:{}'.format(TARGETS))
    FLRTVC_PARAMS = {'apar_type': MODULE.params['apar'],
                     'apar_csv': MODULE.params['csv'],
                     'filesets': MODULE.params['filesets'],
                     'dst_path': MODULE.params['path'],
                     'verbose': MODULE.params['verbose']}
    FORCE = MODULE.params['force']
    # TBC - Temporary - invalidate the force option
    FORCE = False

    CLEAN = MODULE.params['clean']
    CHECK_ONLY = MODULE.params['check_only']
    DOWNLOAD_ONLY = MODULE.params['download_only']

    if (FLRTVC_PARAMS['dst_path'] is None) or (not FLRTVC_PARAMS['dst_path'].strip()):
        FLRTVC_PARAMS['dst_path'] = '/tmp/ansible'
    WORKDIR = os.path.join(FLRTVC_PARAMS['dst_path'], 'work')

    if not os.path.exists(WORKDIR):
        os.makedirs(WORKDIR, mode=0744)

    # metadata
    OUTPUT = {}
    for MACHINE in TARGETS:
        OUTPUT[MACHINE] = {}  # first time init

    # check connecivity
    TARGETS = check_targets(TARGETS, NIM_CLIENTS, OUTPUT)
    logging.debug('Available target machines are:{}'.format(TARGETS))
    if not TARGETS:
        logging.warning('Empty target list')

    # ===========================================
    # Install flrtvc script
    # ===========================================
    logging.debug('*** INSTALL ***')
    _FLRTVCPATH = os.path.abspath(os.path.join(os.sep, 'usr', 'bin'))
    _FLRTVCFILE = os.path.join(_FLRTVCPATH, 'flrtvc.ksh')
    if not os.path.exists(_FLRTVCFILE):
        _DESTNAME = os.path.abspath(os.path.join(os.sep, 'FLRTVC-latest.zip'))
        download('https://www-304.ibm.com/webapp/set2/sas/f/flrt3/FLRTVC-latest.zip', _DESTNAME)
        unzip(_DESTNAME, os.path.abspath(os.path.join(os.sep, 'usr', 'bin')))
    _STAT = os.stat(_FLRTVCFILE)
    if not _STAT.st_mode & stat.S_IEXEC:
        os.chmod(_FLRTVCFILE, _STAT.st_mode | stat.S_IEXEC)

    # ===========================================
    # Run flrtvc script
    # ===========================================
    logging.debug('*** REPORT ***')
    wrong_targets = []
    for MACHINE in TARGETS:
        rc = run_flrtvc(MACHINE, OUTPUT[MACHINE], FLRTVC_PARAMS)
        if rc == 1:
            wrong_targets.append(MACHINE)
    wait_all()
    for machine in wrong_targets:
        logging.warning('Machine: {} will not be updated because of accessibility issue'
                        .format(machine))
        TARGETS.remove(machine)
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
        run_downloader(MACHINE, OUTPUT[MACHINE], OUTPUT[MACHINE]['1.parse'], FORCE)
    wait_all()

    if DOWNLOAD_ONLY:
        MODULE.exit_json(changed=CHANGED, msg='exit on download only', meta=OUTPUT)

    # ===========================================
    # Install efixes
    # ===========================================
    logging.debug('*** UPDATE ***')
    for MACHINE in TARGETS:
        run_installer(MACHINE, OUTPUT[MACHINE], OUTPUT[MACHINE]['4.check'], FORCE)
    wait_all()

    MODULE.exit_json(
        changed=CHANGED,
        msg='FLRTVC completed successfully',
        meta=OUTPUT)
