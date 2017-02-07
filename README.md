# patch_mgmt

# AIX for Ansible

## Requirements

### Platforms

- AIX 6.1
- AIX 7.1
- AIX 7.2

### Ansible

- Requires Ansible 1.2 or newer

## Resources

### suma

Crates a task to automate the download of technology levels (TL) and service packs (SP) from a fix server.

In file syma_list.yml:

List: global config

```
- name: "SUMA List: global config"
  suma:
    operation: list
    list_type: global_config
```

List: default task(s)

```
- name: "SUMA command: List default task"
  suma:
    operation: list
    list_type: default_task
```

List: all tasks

```
- name: "SUMA command: List all tasks"
  suma:
    operation: list
    list_type: list_task
```

