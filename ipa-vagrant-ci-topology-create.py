#!/usr/bin/python3
# Author: Martin Basti
# See LICENSE file for license


import argparse
import copy
import random
import os
import sys
import io
import subprocess
import yaml  # python3-PyYAML
import pwd
import time

DEFAULT_CONFIG_FILENAME = os.path.expanduser("~/.ipa_vagrant_config.yaml")

RPMS_DIR = "rpms"
PROVISIONING_DIR = "provisioning"
VAGRANT_FILE = "Vagrantfile"
ANSIBLE_FILE = "ansible.yml"
CI_CONFIG_FILE = "ipa-test-config.yaml"
CONTROLLER_SSH_KEY = "controller_rsa"
CONTROLLER_SSH_PUB_KEY = "controller_rsa.pub"
IP_ADDR_FIRST = 100

DEFAULT_CONFIG = dict(
    memory_controller=1024,
    memory_server=2048,
    memory_client=1024,
)


PACKAGES = [
    "vim",
    "PyYAML",
    "haveged",
    "bind-dyndb-ldap"
]


DEFAULT_BOX = "f23"

box_mapping = {
    "f22": {"libvirt": { "override.vm.box": "f22",
                         "override.vm.box_url": "http://download.fedoraproject.org/pub/fedora/linux/releases/22/Cloud/x86_64/Images/Fedora-Cloud-Base-Vagrant-22-20150521.x86_64.vagrant-libvirt.box",
                       },
            "virtualbox": { "override.vm.box": "box-cutter/fedora22", },
            "ovirt3": { "domain.template": "ipa-Fedora-23-x86_64-developer-brq", },
    },
    "f23": {"libvirt": { "override.vm.box": "f23",
                         "override.vm.box_url": "http://download.fedoraproject.org/pub/fedora/linux/releases/23/Cloud/x86_64/Images/Fedora-Cloud-Base-Vagrant-23-20151030.x86_64.vagrant-libvirt.box",
                       },
            "virtualbox": { "override.vm.box": "box-cutter/fedora23", },
            "ovirt3": { "domain.template": "ipa-Fedora-22-x86_64-developer-brq", },
    },
}


class IPAVagrantConfig(object):

    def __init__(self, filename=None, parser_args=None):
        self.filename=filename
        self.config = copy.copy(DEFAULT_CONFIG)

        self.load_config_from_file()

        if parser_args:
            self.__add_parser_args(parser_args)

    def __getattr__(self, item):
        try:
            return self.config[item]
        except KeyError:
            raise AttributeError()

    def __add_parser_args(self, parser_args):
        """Check if any of configuration keyword has been passed to parser and
        update configuration.
        """
        for key in self.config.keys():
            try:
                val = getattr(parser_args, key, None)
                if val is not None:
                    self.config[key] = val
            except KeyError:
                pass

    def load_config_from_file(self):
        if self.filename:
            filename = self.filename
        else:
            filename = DEFAULT_CONFIG_FILENAME
            if not os.path.isfile(filename):
                return  # do not fail with default config

        with io.open(filename, "r") as f:
            res = yaml.safe_load(f)

        for key in res.keys():
            if key not in self.config:
                # all known options must be there, if not, please add missing
                # option to DEFAULT_CONFIG variable
                raise KeyError("Unknown option '{}'".format(key))
            elif not isinstance(res[key], type(self.config[key])):
                raise TypeError(
                    "{key} type: expected {expected}, got {got}".format(
                        key=key, expected=type(self.config[key]),
                        got=type(res[key])))
            else:
                self.config[key] = res[key]

    def export_config(self):
        filename = self.get_filename()

        with io.open(filename, "w") as f:
            yaml.safe_dump(self.config, f, default_flow_style=False)
            f.flush()

        return filename

    def get_filename(self):
        if self.filename:
            filename = self.filename
        else:
            filename = DEFAULT_CONFIG_FILENAME

        return filename


class VagrantFile(object):

    CONFIG_TEMPLATE = """
# -*- mode: ruby -*-
# vi: set ft=ruby :
#
NETWORK="{network}" # first three octets
DOMAIN="{domain}"
VM_NAME_PREFIX = "{vm_name_prefix}"

Vagrant.configure(2) do |config|
    {providers}
    {images}
    {boxes}
end
"""

    BOX_TEMPLATE = """
    config.vm.define "{conf_name}" {primary_machine} do |{conf_name}|
        {conf_name}.vm.network "private_network", ip: "#{{NETWORK}}.{ipaddr_last_octet}"
        {conf_name}.vm.hostname = "{conf_name}.#{{DOMAIN}}"

        {conf_name}.vm.provider "libvirt" do |domain|
            domain.memory = {memory}
        end
        {conf_name}.vm.provider "virtualbox" do |domain|
            domain.memory = {memory}
        end
        {conf_name}.vm.provider "ovirt3" do |domain|
            domain.memory = {memory}
            domain.name = "#{{VM_NAME_PREFIX}}-{conf_name}-{time}"
        end

        {conf_name}.vm.provision "shell", inline: <<-SHELL
{shell}
        SHELL
    end
"""

    def __init__(self, domain, box, topology_path, mem_controller, mem_server,
                 mem_client, num_replicas=0, num_clients=0, extra_packages=[],
                 enforcing=False):
        self.domain = domain
        self.box = box
        self.num_replicas = num_replicas
        self.num_clients = num_clients
        self.extra_packages = extra_packages
        self.mem_controller = mem_controller
        self.mem_server = mem_server
        self.mem_client = mem_client
        self.topology_path = topology_path
        self.enforcing = enforcing

        self.network_octets = '192.168.%s' % random.randint(100, 200)
        self.ip_addrs = self._generate_ip_addresses(self.network_octets,
                                                    IP_ADDR_FIRST)

    def _generate_ip_addresses(self, network_24, start_from):
        i = start_from
        ip_addresses = {}

        ip_addresses['controller'] = {
            'ip': '{}.{}'.format(network_24, i),
            'last_octet': i,
        }
        i += 1

        ip_addresses['master'] = {
            'ip': '{}.{}'.format(network_24, i),
            'last_octet': i,
        }
        i += 1

        replicas = {}
        ip_addresses['replicas'] = replicas
        for k in range(1, self.num_replicas + 1):
            replicas['replica%s' % k] = {
                'ip': '{}.{}'.format(network_24, i),
                'last_octet': i,
            }
            i += 1

        clients = {}
        ip_addresses['clients'] = clients
        for k in range(1, self.num_clients + 1):
            clients['client%s' % k] = {
                'ip': '{}.{}'.format(network_24, i),
                'last_octet': i,
            }
            i += 1

        return ip_addresses

    def _generate_ovirt3_configuration(self,
            api_user=None, api_password='Secret123', api_url=None,
            vm_user=None, vm_ssh_private_key=None,
            lab_datacenter='', lab_cluster=''):
        config_name = "ovirt3_user_config.rb"
        USER_CONFIG_TEMPLATE = """
# -*- mode: ruby -*-
# vi: set ft=ruby :
#
OvirtConfig = Hash.new
OvirtConfig[:api] = {{
    :user => "{api_user}",
    :password => "{api_password}",
    :url => "{api_url}",
}}
OvirtConfig[:vm] = {{
    :user => "{vm_user}",
    :ssh_private_key => "{vm_ssh_private_key}",
}}
OvirtConfig[:lab] = {{
    :datacenter => "{lab_datacenter}",
    :cluster => "{lab_cluster}",
}}
"""
        OVIRT_PROVIDER_CONFIG_TEMPLATE = """
    config.vm.provider "ovirt3" do |domain, override|
        # load user config
        require_relative "{ovirt_config}"

        # set API location and credentials
        api_config = OvirtConfig[:api]
        domain.url = api_config[:url]
        domain.username = api_config[:user]
        domain.password = api_config[:password]

        # set VM credentials
        vm_config = OvirtConfig[:vm]
        override.ssh.username = vm_config[:user]
        override.ssh.private_key_path = vm_config[:ssh_private_key]

        # define datacenter and cluster where VM will be created
        lab_config = OvirtConfig[:lab]
        domain.datacenter = lab_config[:datacenter]
        domain.cluster = lab_config[:cluster]

        # define default VM presets
        domain.cpus = 1
        domain.memory = 1024
        domain.console = 'vnc' #could also be 'spice'

        # non-admin users have API filtered
        domain.filtered_api = true
        # lab certificate is not signed by trusted CA
        domain.ca_no_verify = true

        # each provider requires box but here it is just dummy because we use lab template
        override.vm.box = 'dummy'
        override.vm.box_url = 'https://github.com/myoung34/vagrant-ovirt3/blob/master/example_box/dummy.box?raw=true'
    end
"""
        if not all((api_user, vm_user, vm_ssh_private_key)):
            user_info = pwd.getpwuid(os.getuid())
            if not api_user:
                api_user = user_info.pw_name
            if not vm_user:
                vm_user = user_info.pw_name
            if not vm_ssh_private_key:
                vm_ssh_private_key = os.path.join(user_info.pw_dir,
                    '.ssh', 'id_rsa')

        if not api_url:
            api_url = 'https://localhost:443'

        with open(os.path.join(self.topology_path, config_name), 'w') as f:
            f.write(USER_CONFIG_TEMPLATE.format(api_user=api_user,
                api_password=api_password, api_url=api_url,
                vm_user=vm_user, vm_ssh_private_key=vm_ssh_private_key,
                lab_datacenter=lab_datacenter, lab_cluster=lab_cluster))

        return OVIRT_PROVIDER_CONFIG_TEMPLATE.format(ovirt_config=config_name)

    def _generate_provider_specific_images(self, box):
        PROVIDER_IMAGES_OVERRIDE_TEMPLATE = """
    config.vm.provider "{provider}" do |domain, override|
{overrides}
    end
"""
        PROVIDER_IMAGES_OVERRIDE_LINE_TEMPLATE = "\t\t{key} = \"{value}\"\n"
        images = ""
        for provider in box_mapping[box]:
            overrides = ""
            for key in box_mapping[box][provider]:
                overrides += PROVIDER_IMAGES_OVERRIDE_LINE_TEMPLATE.format(
                    key = key,
                    value = box_mapping[box][provider][key],
                )
            images += PROVIDER_IMAGES_OVERRIDE_TEMPLATE.format(
                provider = provider,
                overrides = overrides,
            )
        return images

    def _shell_generate_install_basic_pkgs(self):
        content = [
            "sudo dnf clean all",
            "sudo dnf upgrade dnf* --best --allowerasing -y",  # upgrade dnf to fix it
            "sudo dnf copr enable mkosek/freeipa-master -y",
            "sudo dnf config-manager --set-enabled updates-testing",
            "sudo dnf upgrade --best --allowerasing -y",
            '[ "$(ls -A /vagrant/{rpmdir})" ] && sudo dnf install /vagrant/{rpmdir}/*.rpm --best --allowerasing -y'.format(rpmdir=RPMS_DIR),
        ]

        packages = PACKAGES + self.extra_packages
        if packages:
            content.append(
                "sudo dnf install {} --best --allowerasing -y".format(" ".join(packages))
            )
        return content

    def _shell_generate_resolv_file(self):
        ip_addresses = self.ip_addrs
        content = [
            "sudo echo 'search {}' > /etc/resolv.conf".format(self.domain),
            "sudo echo 'nameserver {}' >> /etc/resolv.conf".format(ip_addresses['master']['ip'])
        ]

        for value in ip_addresses['replicas'].values():
            content.append(
                "sudo echo 'nameserver {}' >> /etc/resolv.conf".format(value['ip'])
            )
        return content

    def _shell_generate_hosts_file(self):
        ip_addresses = self.ip_addrs
        content = [
            "sudo echo '127.0.0.1  localhost' > /etc/hosts",
            "sudo echo '::1  localhost' >> /etc/hosts".format(),
        ]

        for n in ['controller', 'master']:
            content.append(
                "sudo echo '{ip} {name}.{domain}' >> /etc/hosts".format(
                    ip=ip_addresses[n]['ip'],
                    name=n,
                    domain=self.domain,
                ),
            )

        for t in ['replicas', 'clients']:
            for n, v in ip_addresses[t].items():
                content.append(
                    "sudo echo '{ip} {name}.{domain}' >> /etc/hosts".format(
                        ip=v['ip'],
                        name=n,
                        domain=self.domain,
                    ),
                )

        return content

    def _shell_set_hostname(self, hostname):
        if not hostname.endswith(self.domain):
            hostname = '{h}.{d}'.format(h=hostname, d=self.domain)

        return [
            "sudo hostnamectl set-hostname {}".format(hostname)
        ]

    def _shell_generate_enable_haveged(self):
        config = [
            "sudo systemctl start haveged",
            "sudo systemctl enable haveged",
        ]

        return config

    def _shell_generate_create_root_ssh_dir(self):
        content = [
            "sudo bash -c \"[ -d /root/.ssh ] || mkdir -p /root/.ssh\""
        ]
        return content

    def _shell_generate_add_controller_key_to_athorized(self):
        content = self._shell_generate_create_root_ssh_dir() + [
            "sudo cat '/vagrant/{sshpub}' >> /root/.ssh/authorized_keys".format(sshpub=CONTROLLER_SSH_PUB_KEY),
        ]
        return content

    def _shell_generate_cp_controller_key(self):
        content = self._shell_generate_create_root_ssh_dir() + [
            "sudo cp /vagrant/{sshpriv} /root/.ssh/id_rsa".format(sshpriv=CONTROLLER_SSH_KEY)
        ]
        return content

    def _shell_generate_setenforce(self):
        content = [
            "sudo setenforce %s" % ('1' if self.enforcing else '0'),
        ]
        return content

    def generate_vagrant_file(self):
        timestamp=time.time()
        shell_basic_conf = []
        shell_basic_conf.extend(self._shell_generate_setenforce())
        shell_basic_conf.extend(self._shell_generate_install_basic_pkgs())
        shell_basic_conf.extend(self._shell_generate_hosts_file())
        shell_basic_conf.extend(self._shell_generate_resolv_file())
        shell_basic_conf.extend(self._shell_generate_enable_haveged())

        controller = self.BOX_TEMPLATE.format(
            conf_name="controller",
            ipaddr_last_octet=self.ip_addrs['controller']['last_octet'],
            primary_machine=", primary: true",
            memory=self.mem_controller,
            time=timestamp,
            shell='\n'.join(shell_basic_conf +
                            self._shell_generate_cp_controller_key() +
                            self._shell_set_hostname('controller'))
        )

        master = self.BOX_TEMPLATE.format(
            conf_name="master",
            ipaddr_last_octet=self.ip_addrs['master']['last_octet'],
            primary_machine="",
            memory=self.mem_server,
            time=timestamp,
            shell='\n'.join(shell_basic_conf +
                            self._shell_generate_add_controller_key_to_athorized() +
                            self._shell_set_hostname('master'))
        )

        replicas_conf = []
        for name, addr in self.ip_addrs['replicas'].items():
            replica = self.BOX_TEMPLATE.format(
                conf_name=name,
                ipaddr_last_octet=addr['last_octet'],
                primary_machine="",
                memory=self.mem_server,
                time=timestamp,
                shell='\n'.join(shell_basic_conf +
                                self._shell_generate_add_controller_key_to_athorized() +
                                self._shell_set_hostname(name))
            )
            replicas_conf.append(replica)

        clients_conf = []
        for name, addr in self.ip_addrs['clients'].items():
            client = self.BOX_TEMPLATE.format(
                conf_name=name,
                ipaddr_last_octet=addr['last_octet'],
                primary_machine="",
                memory=self.mem_client,
                time=timestamp,
                shell='\n'.join(shell_basic_conf +
                                self._shell_generate_add_controller_key_to_athorized() +
                                self._shell_set_hostname(name))
            )
            clients_conf.append(client)

        boxes_conf_export = "\n".join([
            controller,
            master,
            "\n".join(replicas_conf),
            "\n".join(clients_conf)
        ])

        provider_specific_images = self._generate_provider_specific_images(self.box)
        providers_config = ''
        providers_config += self._generate_ovirt3_configuration()
        prefix = pwd.getpwuid(os.getuid()).pw_name

        return self.CONFIG_TEMPLATE.format(
            vm_name_prefix = prefix,
            providers = providers_config,
            images = provider_specific_images,
            network=self.network_octets,
            domain=self.domain,
            boxes=boxes_conf_export,
        )

    def export_ci_config_file(self, path):
        config = dict()
        config['ad_admin_name'] = "Administrator"
        config['ad_admin_password'] = "Secret123456"
        config['admin_name'] = "admin"
        config['admin_password'] = "Secret123"
        config['debug'] = False
        config['dirman_dn'] = "cn=Directory Manager"
        config['dirman_password'] = "Secret123"
        config['dns_forwarder'] = "10.34.78.1"
        config['nis_domain'] = "ipatest"
        config['ntp_server'] = "1.pool.ntp.org"
        config['root_ssh_key_filename'] = "/root/.ssh/id_rsa"
        config['test_dir'] = "/root/ipatests"

        hosts = []
        master = {
            'name': "{}.{}".format('master', self.domain),
            'external_hostname': "{}.{}".format('master', self.domain),
            'ip': self.ip_addrs['master']['ip'],
            'role': "master",
        }
        hosts.append(master)

        for key, role in [('replicas', 'replica'),('clients', 'client')]:
            for name, addr in self.ip_addrs[key].items():
                hosts.append({
                    'name': "{}.{}".format(name, self.domain),
                    'external_hostname': "{}.{}".format(name, self.domain),
                    'ip': addr['ip'],
                    'role': role,
                })

        domains = [{
            'name': self.domain,
            'type': "IPA",
            'hosts': hosts,
        }]

        config['domains'] = domains

        with io.open(path, 'w') as f:
            yaml.safe_dump(config, f, default_flow_style=False)
            f.flush()
            f.close()


def create_directories(parent_name):
    os.mkdir(parent_name)
    os.mkdir(os.path.join(parent_name, RPMS_DIR))
    os.mkdir(os.path.join(parent_name, PROVISIONING_DIR))


def main():
    parser = argparse.ArgumentParser(description="")
    parser.add_argument("topology_name", type=str,
                        help="Name for topology (directory with this name "
                             "will be created)")
    parser.add_argument("--replicas", dest="replicas", type=int, default=0,
                        metavar="INT",
                        help="Number of IPA replicas to be prepared "
                             "(default: 0)")
    parser.add_argument('--clients', dest="clients", type=int, default=0,
                        metavar="INT",
                        help="Number of IPA clients to be prepared "
                             "(default: 0)")
    parser.add_argument('--domain', dest="domain", type=str,
                        default="ipa.test", help="Domain for provisioned VM "
                                                 "(default: ipa.test)")
    parser.add_argument('--add-package', dest="packages", action="append",
                        help="Allows to specify packages that will be "
                             "installed from repository", default=[],
                        metavar="NAME")
    parser.add_argument('--memory-controller', dest="memory_controller",
                        help="Allows to specify memory for controller [MB]",
                        metavar="MBytes", default=None)
    parser.add_argument('--memory-server', dest="memory_server",
                        help="Allows to specify memory for server [MB]",
                        metavar="MBytes", default=None)
    parser.add_argument('--memory-client', dest="memory_client",
                        help="Allows to specify memory for client [MB]",
                        metavar="MBytes", default=None)
    parser.add_argument('--selinux-enforce', dest="enforcing",
                        action='store_true', default=False,
                        help="Set SELinux to enforce mode")
    parser.add_argument('--box', dest="box", default=DEFAULT_BOX,
                        help="Set box that will be used (default: %s)" %
                             DEFAULT_BOX)
    parser.add_argument('--config-file', dest="config_file", default=None,
                        help="Path to configuration file (default: %s)" %
                        DEFAULT_CONFIG_FILENAME)
    parser.add_argument('--export-config', dest="export_config", default=False,
                        action="store_true", help="export current "
                        "configuration to config file (destination: "
                        "--config-file)")
    parser.add_argument('--show-config', dest="show_config", default=False,
                        action="store_true", help="show current configuration")

    args = parser.parse_args()

    config = IPAVagrantConfig(filename=args.config_file, parser_args=args)

    if args.show_config:
        print("Current configuration:")
        keys = sorted(config.config.keys())
        for key in keys:
            print("    %s: %r" % (key, config.config[key]))
        print("Path to used config file: ", config.get_filename())
        if not args.export_config:
            return

    if args.export_config:
        where = config.export_config()
        print("Configuration saved to %s", where)
        return


    topology_path = os.path.abspath(args.topology_name)
    vagrant_file = VagrantFile(
        args.domain, args.box, topology_path,
        config.memory_controller, config.memory_server,
        config.memory_client, args.replicas, args.clients,
        extra_packages=args.packages,
        enforcing=args.enforcing)

    create_directories(args.topology_name)

    # generate SSH keys for controller
    command = [
        "ssh-keygen",
        "-f", str(os.path.join(args.topology_name, CONTROLLER_SSH_KEY)),
        "-P", "",
    ]
    proc = subprocess.Popen(command)
    try:
        outs, errs = proc.communicate(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()
        raise RuntimeError("Timeout during generating SSH keys")
    else:
        if proc.returncode is not None and proc.returncode != 0:
            raise RuntimeError("Failed to generate SSH key: %s" % errs)

    with io.open(os.path.join(topology_path, VAGRANT_FILE), "w") as f:
        f.write(vagrant_file.generate_vagrant_file())
        f.close()

    vagrant_file.export_ci_config_file(os.path.join(args.topology_name,
        CI_CONFIG_FILE))

if __name__ == '__main__':
    try:
        main()
    except RuntimeError as e:
        print(e, file=sys.stderr)
        sys.exit(2)

