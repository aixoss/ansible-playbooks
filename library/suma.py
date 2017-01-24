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

DOCUMENTATION = '''
---
module: suma
author: "Cyril Bouhallier"
version_added: "1.0.0"
short_description: AIX suma command
requirements: [ AIX ]
description:
    - Create a task to automate the dowload of AIX technology level and service packs from a fix server

# Field:
#     description:
#       - A comma-separated list of FIELD to be used.
#     required: false
#     default: None
#     version_added: "2.1"

# Run SUMA using a specific FIELD
# - suma:
#     field: FilterDir,FilterML,MaxDLSize
'''

EXAMPLES = '''
# To list SUMA tasks:
- suma:
    Task: List
    Taskid: TaskID

# To list or edit the default SUMA task:
- suma:
    Task: [List, Edit]
    Field: Value

# To list or edit the SUMA global configuration settings:
- suma:
    Task: [List, Edit]
    Field: Value

# To unschedule a SUMA task:
- suma:
    Task: Unschedule
    Field: TaskID

# To delete a SUMA task:
- suma:
    Task: Delete
    Field: TaskID
'''

# ===========================================
# Module code.
#

def main():

    module = AnsibleModule(
        argument_spec = dict(
            task    = dict(choices=['create', 'edit', 'execute', 'list', 'schedule', 'unschedule', 'delete',], type='str'),
            task_id = dict(required=False, type='int'),
            list_id = dict(required=False, choices=['global_config','default_task','list_task'], type='str'),
            field   = dict(required=False, type='dict'),
            repeats = dict(required=False, type='bool'),
        ),
        supports_check_mode = True
    )

    # ===========================================
    # Get Module params
    # ===========================================

    task    = module.params.get('task')
    task_id = module.params.get('task_id')
    list_id = module.params.get('list_id')
    field = module.params.get('field')
    repeats = module.params.get('repeats')

    ###########################################################################
    # Execute Execute Execute Execute Execute Execute
    ###########################################################################

    if task == 'execute':
      if field:

        ###########################################################################
        # RqName field must be blank when RqType equals Latest.
        ###########################################################################

        if 'Rqtype' in field and 'RqName' in field and field['Rqtype'] == 'Latest':

            del field['RqName']

            cmd = ''.join( ['-a %s=%s ' % (key, value) for (key, value) in field.items()] )
            cmd = 'echo ' + cmd

            rc, stdout, stderr = module.run_command(cmd)

            if rc == 0:
              module.exit_json(
               changed=False,
               message='SUMA Execute task: {}'.format(cmd),
               debug_out=stdout.split('\n'))
            else:
              module.fail_json(msg='SUMA Execute (RqName blank) returned non-0 exit - STDERR:{}'.format(stderr.split('\n')))

        else:

          cmd = ''.join( ['-a %s=%s ' % (key, value) for (key, value) in field.items()] )
          cmd = '/usr/sbin/suma -x ' + cmd

          rc, stdout, stderr = module.run_command(cmd)

          if rc == 0:
            module.exit_json(
              changed=False,
              message='SUMA Execute task: {}'.format(cmd),
              debug_out=stdout.split('\n'))
          else:
            module.fail_json(msg='SUMA Execute returned non-0 exit - STDERR:{}'.format(stderr.split('\n')))

      ##############################
      ## Build DLTarget directory
      ##############################

      elif 'DLTarget' in field:

##        module.run_command('mkdir' % field.get('DLTarget'))

        cmd = ''.join( ['-a %s=%s ' % (key, value) for (key, value) in field.items()] )
        # cmd = '/usr/sbin/suma -x ' + cmd
        cmd = 'echo ' + cmd

        rc, stdout, stderr = module.run_command(cmd)

        if rc == 0:
          module.exit_json(
            changed=False,
            message='SUMA Execute task: {}'.format(cmd),
            debug_out=stdout.split('\n'))
        else:
          module.fail_json(msg='SUMA Execute (DLT) returned non-0 exit - STDERR:{}'.format(stderr.split('\n')))

    ###########################################################################
    # TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO
    ###########################################################################

    # ===========================================
    # Edit: Global configuration settings
    # ===========================================

    # suma -c [ -a Field=Value ]...

    # ===========================================
    # Unschedule: SUMA task
    # ===========================================

    # suma -u TaskID

    # ===========================================
    # Delete: SUMA task
    # ===========================================

    # suma -d TaskID

    # ===========================================
    # Schedule: SUMA task
    # ===========================================

    # suma -s "30 2 15 * *" -a RqType=Latest -a DisplayName="Latest fixes - 15th Monthly"


# Ansible module 'boilerplate'
from ansible.module_utils.basic import *

if __name__ == '__main__':
      main()
