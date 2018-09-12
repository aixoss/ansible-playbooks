---
- name: "VIOS upgrade on AIX"
  hosts: all
  gather_facts: no
  vars:
    log_file: "/tmp/ansible_vios_upgrade_debug.log"
    backup_prefix: "vro_ios_bckp"
    backup_location: "/export/nim/ios_backup"

  tasks:

    #- name: "AIX VIOS HEALTH CHECK"
    #  aix_nim_vios_hc:
    #    description: 'Check the VIOS(es) can be updated'
    #    targets: "(gdrh10v1) (gdrh10v2) (gdrh9v1,gdrh9v2)"
    #    action: "health_check"
    #    vars: "{{ vars }}"
    #
    #  register: hc_result


    - name: "AIX NIM VIOS Backup"
      aix_nim_upgradeios:
        description: 'Create a vios backup'
        action: "backup"
        #targets: "(p7juav1,p7juav2) (p7jufv1,p7jufv2)"
        targets: "p7juav1"
        #vios_status: "{{ hc_result.status }}"
        vars: "{{ vars }}"
        backup_prefix: "{{ vars.backup_prefix }}"
        location: "{{ vars.backup_location }}"
        #time_limit: "mm/dd/yyyy hh:mm"

      register: backup_result


    - name: "AIX NIM VIOS View Backup"
      aix_nim_upgradeios:
        description: 'Display vios backup information'
        action: "view_backup"
        #targets: "(p7juav1,p7juav2) (p7jufv1,p7jufv2)"
        targets: "p7juav1"
        vios_status: "{{ backup_result.status }}"
        vars: "{{ vars }}"
        backup_prefix: "{{ vars.backup_prefix }}"


    - name: "AIX NIM VIOS upgrade and restore backup"
      aix_nim_upgradeios:
        description: 'Upgrade vios and restore vios backup'
        action: "upgrade_restore"
        #targets: "(p7juav1,p7juav2) (p7jufv1,p7jufv2)"
        targets: "p7juav1"
        vios_status: "{{ backup_result.status }}"
        vars: "{{ vars }}"
        #backup_prefix: "{{ vars.backup_prefix }}"
        boot_client: "yes"
        resolv_conf: ""
        spot_prefix: ""
        mksysb_prefix: ""
        bosinst_data_prefix: ""
        #time_limit: "mm/dd/yyyy hh:mm"

      register: upgrade_result

    ## Use this section to restore a backup previously created without upgrade
    #- name: "AIX NIM VIOS Restore Backup"
    #  aix_nim_upgradeios:
    #    description: 'Restore a vios backup'
    #    action: "restore_backup"
    #    #targets: "(p7juav1,p7juav2) (p7jufv1,p7jufv2)"
    #    targets: "p7juav1"
    #    #vios_status: "{{ backup_result.status }}"
    #    vars: "{{ vars }}"
    #    backup_prefix: "{{ vars.backup_prefix }}"
    #
    #  register: restore_result

    #- debug: var=hc_result.output
    - debug: var=backup_result.output
    - debug: var=upgrade_result.output
    #- debug: var=restore_result.output


