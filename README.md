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


Parameters:
* `operation` - name of the service as it appears in the first field of `/etc/inetd.conf`
* `list_type` - type of service. Valid values: `dgram stream sunrpc_udp sunrpc_tcp`

### tcpservice

Manage the services started by `/etc/rc.tcpip`. Example:

```ruby
aix_tcpservice 'xntpd' do
  action :enabled
end
```

Parameters:

* `immediate` (optional) - whether to start/stop the TCP/IP service
  immediately by contacting the SRC. It's much better to declaratively
  specify this separately using the built-in `service` resource in
  Chef.

### toolboxpackage

To install packages from the IBM AIX Toolbox for Linux off the IBM FTP
site. Example:

```ruby
aix_toolboxpackage "a2ps" do
  action :install
end
```

Parameters:

* `base_url` (optional) - the base URL to use to retrieve the package.
  If you are behind a firewall or your AIX system doesn't have access
  to the Internet, you can override this to an HTTP/FTP server where
  you have stored the RPMs.

### chdev

Change any AIX device attribute. Example:

```ruby
aix_chdev 'sys0' do
  attributes(maxuproc: '1026', ncargs: '1024')
  need_reboot false
  action :update
end

aix_chdev 'fcs0' do
  attributes(num_cmd_elems: '200', max_xfer_size: '0x800000')
  need_reboot true
  action :update
end

aix_chdev 'ent0' do
  attributes(poll_uplink: 'yes')
  need_reboot true
  action :update
end

aix_chdev 'hdisk1" do
  attributes(reserve_policy: 'no_reserve')
  hot_change true
  action:update
end
```

Parameters:

* `need_reboot` (optional) - Add -P to the chdev command if device is busy (this parameter cannot be used with hot_change)
* `hot_change` (optional) - Add -U to the chdev command for attribute with True+ (this parameter cannot be used with need_reboot)

### pagingspace

Create, remove, modify AIX paging space. Example:

```ruby
aix_pagingspace "Changing paging space" do
  name 'hd6'
  size 1024
  auto true
  action :change
end

aix_pagingspace "Disabling paging space" do
  name 'paging00'
  active false
  action :change
end

aix_pagingspace "Removing paging space" do
  name 'paging00'
  action :remove
end

aix_pagingspace "Creating paging space" do
  name 'mypgsp'
  size 1024
  auto true
  vgname 'rootvg'
  action :create
end

aix_pagingspace "Creating paging space 2" do
  name 'mypgsp2'
  size 1024
  auto true
  active true
  vgname 'rootvg'
  action :create
end
```

Parameters:

* `name` - Name of the paging space
* `size` - Size of the paging space in MB
* `auto` - Active paging space on reboot (True,False)
* `active` - Active/Desactive paging space  (True,False)
* `vgname` - Volume group name where the paging space should be created

Actions:

* `change` - Modify the paging space
* `remove` - Remove the paging space
* `create` - Create the paging space

### no

Change any AIX no (network) tunables. Example:

```ruby
aix_no "changing no tunables" do
  tunables(udp_recv_perf: '0', udprecvspace: '42083', psetimers: '23')
  set_default
  action :update
end

aix_no "reseting no tunables" do
  tunables(udp_recv_perf: '0', udprecvspace: '0')
  set_default false
  action :reset
end

aix_no "reseting all no tunables" do
  action: reset_all
end

aix_no "reseting all no tunables reboot needed" do
  action: reset_all_with_reboot
end
```

Parameters:

* `set_default` (optional) (default true) - All change are persistant to reboot (/etc/tunables/nextboot)
* `bootlist` (optional) (default false) - If set to true, the bootlist is not changed

Actions:

* `update` - update a list of tunables
* `reset` - reset a list of tunabes
* `reset_all` - reset all tunables to default
* `reset_all_with_reboot` - reset all tunables to default even if the ones that need a reboot

### tunables

Change any AIX unrestricted tunables(vmo, ioo, schedo). Example:

```ruby
aix_tunables "reset schedo values" do
  mode :schedo
  action :reset_all
  permanent
end

aix_tunables "change vpm_throughput_mode" do
  mode :schedo
  tunables(:vpm_throughput_mode => 2)
  permanent
end

aix_tunables "change posix AIO servers" do
  mode :ioo
  tunables(posix_aio_minservers: 6, posix_aio_maxservers: 36)
end

aix_tunables "tune minperm%" do
  mode :vmo
  tunables( :"minperm%" => 6)
  permanent
end

aix_tunables "tune tcp buffers" do
  mode :no
  tunables( :udp_recvspace => 655360, :udp_sendspace => 65536 )
  permanent
end
```

Parameters:

* `mode` (mandatory) (no default) - must be :ioo, :vmo or :schedo
* `permament` (optional) (default false) - All changes are persistent
* `nextboot` (optional) (default false) - All changes applied on next boot only

Actions:

* `update` - update a list of tunables
* `reset` - reset a list of tunabes
* `reset_all` - reset all tunables to default

### multibos

Create, remove or update multibos on AIX. Example:

```ruby
aix_multibos "create a multibos no bootlist" do
  action :create
  bootlist true
end

aix_multibos "create and update a multibos" do
  action :create
  update_device "/mnt/7100-03-05-1524"
end

aix_multibos "remove standby multibos" do
  action :remove
end

aix_multibos "update a multibos" do
  action :update
  update_device "/mnt/7100-03-05-1524"
end

aix_multibos "mount a bos" do
  action :mount
end

aix_multibos "mount a bos" do
  action :umount
end
```

Parameters:

*  `update_device` (optional) - mount point used for update

Actions:

* `create` - create (and update if needed) a bos instance
* `remove` - remove a standby bos
* `update` - update all already create bos
* `mount` - mount a standby bos
* `umount` - umount a standby bos

### chsec
Changes the attributes in the security stanza files.

```ruby
aix_chsec '/etc/security/login.cfg' do
  attributes(maxlogins: '16000', maxroles: '7', shells: '/bin/sh,/usr/bin/ksh')
  stanza 'usw'
  action :update
end
```

Parameters:

* `file_name` (name_attribute) - security file to change
* `attribute` - array of attribut to change
* `stanza` - stanza to change

### etchosts

Add, change or remove entries in the /etc/hosts file.

```ruby
aix_etchosts "test" do
  ip_address "1.1.1.1"
  action :add
end

aix_etchosts "test" do
  ip_address "2.2.2.2"
  action :change
end

aix_etchosts "test" do
  new_hostname "test2"
  action :change
end

aix_etchosts "test" do
  ip_address "1.1.1.1"
  aliases ["test2", "test3"]
  action :add
end

aix_etchosts "test" do
  action :delete
end

aix_etchosts "delete all entries" do
  action :delete_all
end
```

Parameters:

* `name` - name of the host to change/add/delete
* `ip_address` - ip address
* `new_hostname` - new_hostame (use with change action)
* `aliases` - aliases

Actions:
* `add`  - add an entry in /etc/hosts
* `delete` - remove an entry in /etc/hosts
* `delete_all` - remove all entries in /etc/hosts
* `change` - change an entry in /etc/hosts

### niminit

Use niminit to configure the nimclient package.
This will look if /etc/niminfo exists and create it if it does not exist.
You can the use nimclient provider after niminiting the client.

```ruby
aix_niminit node[:hostname] do
  master "nimmaster"
  connect "nimsh"
  pif_name node[:network][:default_interface]
  action :setup
end

aix_niminit node[:hostname] do
  action :remove
end

aix_niminit node[:hostname] do
  master "nimmaster"
  connect "nimsh"
  pif_name "en1"
  action :setup
end
```
Parameters:

* `name` - hostname of the nimclient
* `master` - hostname of the nim master
* `pif_name` - interface name
* `connect` - nimsh or shell

Actions:
* `setup` - setup the nimclient
* `remove` - remove nimclient configuration

### nimclient

Use nimclient to install packages, update service pack, or technology level.
Your NIM server should meet these requirements to work with the nimclient provider:
* All resources name must end with the type of the resource (check example below):
 * 7100-03-05-1514-lpp_source
 * 7100-03-05-1514-spot
 * myinstallpbundle-installp_bundle
* All spot and lpp_source must match the exact oslevel output. To find the next available lpp_source or spot the provider is checking for your oslevel and comparing it with the lpp_source name
 * 7100-03-01-1341-lpp_source
 * 7100-03-02-1412-lpp_source
 * 7100-03-03-1415-lpp_source
 * 7100-03-04-1441-lpp_source
 * 7100-03-05-1524-lpp_source
 * 7100-03-01-1341-spot
 * 7100-03-02-1412-spot
 * 7100-03-03-1415-spot
 * 7100-03-04-1441-spot
 * 7100-03-05-1524-spot

Recommendation: create all the lpp_source with the simage attribute to avoid ambiguity.

```
$ lsnim -l 7100-03-05-1524-lpp_source
7100-03-05-1524-lpp_source:
   class       = resources
   type        = lpp_source
   arch        = power
   Rstate      = ready for use
   prev_state  = unavailable for use
   location    = /export/nim/lpp_source/7100-03-05-1524
   simages     = yes
   alloc_count = 1
   server      = master
```

Here are a few examples of recipes using nimclient:

```ruby
aix_nimclient "updating to latest available sp" do
  installp_flags "aXYg"
  lpp_source "latest_sp"
  fixes "update_all"
  action :cust
end

aix_nimclient "installing filesets from the latest available tl" do
  installp_flags "aXYg"
  lpp_source "latest_tl"
  filesets ["openssh.base.client","openssh.base.server","openssh.license"]
  action :cust
end

aix_nimclient "installing filesets from the next sp" do
  installp_flags "aXYg"
  lpp_source "next_sp"
  filesets ["security.pkcs11.tools"]
  action :cust
end

aix_nimclient "installing filesets" do
  installp_flags "aXYg"
  lpp_source "latest_sp"
  filesets ["Java6_64.samples"]
  action :cust
end

aix_nimclient "reset" do
  action :reset
end

aix_nimclient "deallocate" do
  action :deallocate
end

aix_nimclient "set date to nimmaster value" do
  action :set_date
end

aix_nimclient "disable push operations" do
  action :disable_push
end

aix_nimclient "enable push operations" do
  action :enable_push
end

aix_nimclient "maintbooting client" do
  spot "7100-03-01-1341-spot"
  action :maint_boot
end

aix_nimclient "bos_inst client" do
  spot "7100-03-01-1341-spot"
  lpp_source "7100-03-01-1341-lpp_source"
  action :bos_inst
end

aix_nimclient "allocating resources" do
  installp_bundle "toolbox-installp_bundle"
  lpp_source "7100-03-01-1341-lpp_source"
  spot "7100-03-01-1341-spot"
  action :allocate
end
```

Parameters:

* `spot` (optional) - name of the spot
* `lpp_source` (optional) - name of the lpp_source
* `installp_bundle` (optional) - name of the installp_bundle
* `filesets` - list of filesets to install
* `fixes` - fixe to install
* `installp_flags` - flags used for installp

Actions:

* `allocate` - create (and update if needed) a bos instance
* `deallocate` - remove a standby bos
* `cust` - update all already create bos
* `enable_push` - allow push operation from client
* `disable_push` -  disable push operation from client
* `set_date` - set date to that of the nim master
* `enable_crypto` - enable secure nimsh
* `disable_crypto` - disable secure nimsh
* `reset` - reset the client
* `bos_inst` - enable bos_install installation (you need to reboot the virtual machine after that)
* `maint_boot` - ennable maintenance boot (you need to reboot the virtual machine after that)

### bootlist

Change AIX bootlist. Example:

```ruby
aix_bootlist 'invalidate normal mode bootlist' do
  action :invalidate
  mode :normal
end

aix_bootlist 'set normal and service bootlist on hdisk0' do
  mode :both
  devices ["hdisk0"]
end

aix_bootlist 'set bootlist for normal mode' do
  mode :normal
  devices ["hdisk0","hdisk1"]
  device_options("hdisk0" => "pathid=0", "hdisk1" => "pathid=0,1")
end
```

Parameters:

* `mode` (mandatory) (no default) - must be :both, :normal or :service
* `devices` (no default) - List boot devices to setup
* `device_options` (optional) (default false) - Specify boot options for specific device

Actions:

* `update` - update bootlist
* `invalidate` - invalidate the bootlist

### altdisk

Create an alternate disk on a free disk
Update an existing alternate disk

```ruby
aix_altdisk "cloning rootvg by name hdisk3" do
  type :name
  value "hdisk3"
end

aix_altdisk "cloning rootvg by size 66560" do
  type :size
  value "66560"
end

aix_altdisk "cloning rootvg by size 66561" do
  type :size
  value "66561"
end

aix_altdisk "cloning rootvg by auto" do
  type :auto
  value "bigger"
  action :create
  altdisk_name "myvg"
end

aix_altdisk "cleanup alternate rootvg" do
  action :cleanup
  altdisk_name "rootvg_alt"
end

aix_altdisk "altdisk_by_auto" do
  type :auto
  value "bigger"
  change_bootlist true
  action :create
end

aix_altdisk "altdisk_wake_up" do
  action :wakeup
end

aix_altdisk "altdisk_update" do
  image_location "/mnt/7100-03-05-1524"
  action :customize
end

aix_altdisk "altdisk_sleep" do
  action :sleep
end

aix_altdisk "rename altdisk" do
  new_altdisk_name "altdisk_vg"
  action :rename
end
```

Parameters:

* `type` (optional) - size (choose the disk on which creating the alternate disk by it's size in MB)
* `type` (optional) - name (choose the disk on which creating the alternate disk by it's name)
* `type` (optional) - auto (automatically choose the disk on which creating the rootvg)
* `value` (optional) - bigger (if type is auto choose a disk bigger than the current rootvg size)
* `value` (optional) - equal (if type is auto choose a disk with the exact same size of the rootvg size)
* `value` (optional) - size or name (if type is size or name it's the size or the exact name of the disk)
* `altdisk_name` (optional) - name of the alternate disk to create
* `change_bootlist` (optional) (default false) - change the bootlist to boot to the new alternate disk
* `image_location` (optional) - directory containing filesets used for the cust operation
* `new_altdisk_name` (optional) - new name use for rename action

Actions:

* `create` - create an alternate rootvg disk
* `cleanup` - cleanup an alternate rootvg disk
* `wakeup` - wakeup an alternate rootvg disk
* `rename` - rename an alterante rootvg disk
* `sleep` - put an alternate rootvg in sleep
* `customize` - customiz an alternate rootvg (update)

### fixes

Install and remove fixes
Example:

```ruby
aix_fixes "removing all fixes" do
  fixes ["all"]
  action :remove
end

aix_fixes "installing fixes" do
  fixes ["IV75031s5a.150716.71TL03SP05.epkg.Z", "IV77596s5a.150930.71TL03SP05.epkg.Z"]
  directory "/root/chefclient"
  action :install
end

aix_fixes "removing fix IV75031s5a" do
  fixes ["IV75031s5a", "IV77596s5a"]
  action :remove
end
```

Parameters:

* `fixes` (mandatory) - Array of fixes to install or remove
* `directory` (optional) - Directory where stands the fixes to install

Actions:

* `install` - install fixes
* `remove` - remove fixes

### volume_group

Create or modify a LVM volume group

```ruby
# Create volume groupe 'datavg1' with 2 disks
aix_volume_group 'datavg1' do
  physical_volumes          ['hdisk1', 'hdisk2']
  action :create
end

# Modify existing volume groupe 'datavg1' and add new disk
aix_volume_group 'datavg1' do
  physical_volumes          ['hdisk1', 'hdisk2', 'hdisk3']
  action :create
end

# Create a volume group called `datavg2` comprising 3 disks and assign them to a mirror pool.
aix_volume_group 'datavg2' do
  physical_volumes ['hdisk4', 'hdisk5', 'hdisk6']
  mirror_pool_name   'copy0pool'
  action :create
end

# Add a disk as a hot spare to the same `datavg3` volume group
aix_volume_group 'datavg3' do
  physical_volumes ['hdisk7']
  use_as_hot_spare   'y'
  action :add
end
```

Parameters:
* `name`: Name of the volume group
* `physical_volumes`: The device or list of devices to use as physical volumes (if they haven't already been initialized as * `physical volumes, they will be initialized automatically)
* `use_as_hot_spare`: (optional) Sets the sparing characteristics of the physical volume such that it can be used as a hot spare. Legal values are "y" or "n". "y" marks the disk as a hot spare within the volume group it belongs to. "n" removes the disk from the hot spare pool for the volume group.
* `mirror_pool_name`:   (optional) Assigns or reassigns the disk to the named mirror pool. The mirror pool is created if it does not exist already Mirror pool names can only contain alphanumeric characters, may not be longer than 15 characters, must be unique in the volume group.

Actions:
* `create` - (default) Creates or modify a volume group

### logical_volume

Create or modify a LVM logical volume

```ruby
# create logical volume 'home' of 512MB with 2 copies in volume group 'datavg'
aix_logical_volume 'home' do
  group 'datavg'
  size   512 //  MB
  copies 2
  action :create
end
```

Parameters:
* `name`: Name of the logical volume
* `volume_group`: Volume group in which to create the new logical volume (not required if the volume is declared inside of an `lvm_volume_group` block)
* `size`: Minimum size of the logical volume in MB. The actual size allocated my be slightly greater.
* `copies`: (optional) Number of copies of each logical partition. Legal values are 1, 2, 3

Actions:
* `create` -    (default) Creates or modifies an AIX JFS2 logical volume

### filesystem

Create, modify, mount or defrag a LVM filesystem

```ruby
# create filesystem of 256Mb in '/lvm/folder1' on logical volume 'part1'
aix_filesystem '/lvm/folder1' do
  logical 'part1'
  size   '256M'
  action :create
end

# mount '/lvm/folder1' filesystem
aix_filesystem '/lvm/folder1' do
  action :mount
end

# defrag '/lvm/folder1' filesystem
aix_filesystem '/lvm/folder1' do
  action :defragfs
end

# umount '/lvm/folder1' filesystem
aix_filesystem '/lvm/folder1' do
  action :umount
end
```

Parameters:
* `name`: Mount point of the filesystem
* `logical`: Specifies an existing logical volume on which to make the filesystem
* `size`: Size of the filesystem. It's can be a set of 512k blocks, a size in M or a size in G

Actions:
* `create`: (default) Creates or modifies a filesystem
* `mount`: Mount a filesystem
* `umount`: Unmount a filesystem
* `defragfs`: Defrag a filesystem

### wpar

Manage wpar

#### install aix-wpar gem

The cookbook itself will install the **aix-wpar** gem if the system as internet access.

Else you need to download the gem file [here](https://github.com/adejoux/aix-wpar/releases/tag/v0.1.0).
And install the package on the AIX system:
```bash
/opt/chef/embedded/bin/gem install /tmp/aix-wpar-0.1.0.gem
```

#### recipe example
```ruby
aix_wpar 'create wpar' do
  action :create
  name 'testwpar'
  hostname 'testwpar'
  cpu '10%-50%,100%'
  live_stream true
  autostart true
end

aix_wpar 'stop wpar' do
 action :stop
 name 'testwpar'
 live_stream true
end

aix_wpar 'sync wpar' do
 action :sync
 name 'testwpar'
end

aix_wpar 'delete wpar' do
 action :delete
 name 'testwpar2'
end
```

Parameters:

* `name`: WPAR name
* `hostname`: specify wpar hostname(can be different of wpar name)
* `address`: ip address to use if no entry in /etc/hosts or DNS.
* `interface`: network interface to use
* `rootvg`: to build a rootvg wpar
* `rootvg_disk`: hdisk to use for rootvg wpar
* `wparvg`: volume group to use for system wpar. Default: **rootvg**
* `backupimage`: backup image to restore when building wpar
* `cpu`: resource control CPU. Example: **10%-50%,100%**
* `memory`: resource control memory.
* `autostart`: auto start wpar at boot.
* `live_stream`: live stream wpar commands output


Actions:

* `create` - create a wpar
* `delete` - delete a wpar
* `start` - start a wpar
* `stop`- stop a wpar
* `sync`- synchronize software between system and wpar

* `reset_all` - reset all tunables to default


## License and Authors
* Author:: Julian C. Dunn (<jdunn@chef.io>)
* Author:: Christoph Hartmann (<chris@lollyrock.com>)
* Author:: Benoit Creau (<benoit.creau@chmod666.org>)
* Author:: Alain Dejoux (<adejoux@djouxtech.net>)
* Author:: Alan Thatcher (<alanwthatcher@gmail.com>)
* Author:: Laurent GAY for IBM (<lgay@us.ibm.com>)

