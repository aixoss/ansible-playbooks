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

# Run SUMA using a specific FIELD
# - suma:
#     operation: execute
#     field:
#       Action: preview
#       RqType: TL
#       RqName: 7100-02-02-1316
#       FilterML: 7100-02
#       DisplayName: '"Testing my SUMA module"'
'''

EXAMPLES = '''
# To list SUMA tasks:
- suma:
    Operation: List
    taskid: TaskID

'''

# ===========================================
# Module code.
#

def main():

    module = AnsibleModule(
        argument_spec = dict(
            operation = dict(choices=['create', 'edit', 'execute', 'list', 'schedule', 'unschedule', 'delete',], type='str'),
            task_id   = dict(required=False, type='int'),
            list_type = dict(required=False, choices=['global_config','default_task','list_task'], type='str'),
            field     = dict(required=False, type='dict'),
            repeats   = dict(required=False, type='bool'),
        ),
        supports_check_mode = True
    )

    # ===========================================
    # Get Module params
    # ===========================================

    operation = module.params.get('operation')
    task_id = module.params.get('task_id')
    list_type = module.params.get('list_type')
    field = module.params.get('field')
    repeats = module.params.get('repeats')

    ###########################################################################
    # Execute Execute Execute Execute Execute Execute
    ###########################################################################

    if operation == 'execute':

      ###########################################################################
      # RqName field must be blank when RqType equals Latest.
      ###########################################################################

      # if 'Rqtype' in field and 'RqName' in field and field.get('Rqtype') == 'Latest':
      if 'Rqtype' in field :

        del field['RqName']

        cmd = ''.join( ['-a %s=%s ' % (key, value) for (key, value) in field.items()] )
        cmd = 'echo ' + cmd

        rc, stdout, stderr = module.run_command(cmd)

        debug_dict = []
        debug_dict.append('Dictionnary length: {}'.format(len(recipe)))
        debug_dict.append('Dictionnary keys: {}'.format(recipe.keys()))
        debug_dict.append('Dictionnary values: {}'.format(recipe.values()))
        debug_dict.append('Command: {} '.format(cmd))

        if rc == 0:
          module.exit_json(
            changed=False,
            message='SUMA Execute task: {}'.format(cmd),
            debug_out=stdout.split('\n'))
        else:
          module.fail_json(msg='SUMA Execute (RqName blank) returned non-0 exit - STDERR:{}'.format(stderr.split('\n')))

          # module.exit_json(
          #   changed=False,
          #   debug_dict=debug_dict)
          # module.exit_json(
          #   changed=False,
          #   debug_dict=stdout)

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
            message='SUMA Execute: {}'.format(cmd),
            debug_out=stdout.split('\n'))
        else:
          module.fail_json(msg='SUMA Execute (DLT) returned non-0 exit - STDERR:{}'.format(stderr.split('\n')))

      else:

      # if 'style' in recipe:
      #   debug_dict.append('Dictionnary Style = {}'.format(recipe.get('style')))


        cmd = ''.join( ['-a %s=%s ' % (key, value) for (key, value) in field.items()] )
        cmd = '/usr/sbin/suma -x ' + cmd

        rc, stdout, stderr = module.run_command(cmd)

        if rc == 0:
          module.exit_json(
            changed=False,
            message='SUMA Execute: {}'.format(cmd),
            debug_out=stdout.split('\n'))
        else:
          msg = 'SUMA command: {} returned non-0 exit :{}'.format(cmd, stderr)
          # module.fail_json(msg='SUMA Execute returned non-0 exit - STDERR:{}'.format(stderr.split('\n')))
          module.fail_json(msg=msg)

          # module.exit_json(
          #   changed=False,
          #   debug_dict=debug_dict)
          # module.exit_json(
          #   changed=False,
          #   debug_dict=stdout)

    ###########################################################################
    # List List List List List List List List List List List List List List
    ###########################################################################

    elif operation == 'list' and list_type == 'list_task':

      # ===========================================
      # List: Tasks or Tasks with TaskID
      # ===========================================

      if task_id:
          cmd = '/usr/sbin/suma -l %s' % task_id
          rc, stdout, stderr = module.run_command(cmd)
          # ERROR: 0500-048 Task ID 1 was not found
      else:
          cmd = '/usr/sbin/suma -l'
          rc, stdout, stderr = module.run_command(cmd)

      if rc == 0:
          module.exit_json(
              changed=False,
              message='SUMA List: {} with TaskID:{}'.format(operation, task_id),
              debug_out=stdout.split('\n'))
      else:
          msg = 'SUMA command: {} returned non-0 exit :{}'.format(cmd, stderr)
          module.fail_json(msg=msg)

    # ===========================================
    # List: Global Config
    # ===========================================

    elif operation == 'list' and list_type == 'global_config':

      cmd = '/usr/sbin/suma -c'
      rc, stdout, stderr = module.run_command(cmd)

      if rc == 0:
          module.exit_json(
              changed=False,
              message='SUMA List:{} with TaskID:{}'.format(operation, task_id),
              debug_out=stdout.split('\n'))
      else:
          module.fail_json(msg='SUMA command returned non-0 exit {}'.format(stderr))

    # ===========================================
    # List: Default task
    # ===========================================

    elif operation == 'list' and list_type == 'default_task':

      cmd = '/usr/sbin/suma -D'
      rc, stdout, stderr = module.run_command(cmd)

      if rc == 0:
          module.exit_json(
              changed=False,
              message='SUMA List:{} with TaskID:{}'.format(operation, task_id),
              debug_out=stdout.split('\n'))
      else:
          module.fail_json(msg='SUMA command returned non-0 exit {}'.format(stderr))

    ###########################################################################
    # TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO
    ###########################################################################

    # ===========================================
    # Edit: Global configuration settings
    # ===========================================

    # suma -c [ -a Field=Value ]...

    # ===========================================
    # Unschedule: SUMA operation
    # ===========================================

    # suma -u TaskID

    # ===========================================
    # Delete: SUMA operation
    # ===========================================

    # suma -d TaskID

    # ===========================================
    # Schedule: SUMA operation
    # ===========================================

    # suma -s "30 2 15 * *" -a RqType=Latest -a DisplayName="Latest fixes - 15th Monthly"


# Ansible module 'boilerplate'
from ansible.module_utils.basic import *

if __name__ == '__main__':
      main()
