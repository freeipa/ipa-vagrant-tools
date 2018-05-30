#!/usr/bin/python3
# Author: Martin Basti
# See LICENSE file for license

import random
import os
import sys
import io
import pwd
import time
import subprocess
import logging

import yaml  # python3-PyYAML

from . import constants
from .config import IPAVagrantConfig


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
        {conf_name}.vm.provider "libvirt" do |domain,override|
            domain.memory = {memory}
            override.vm.network "private_network",
                                ip: "#{{NETWORK}}.{ipaddr_last_octet}"
            override.vm.hostname = "{conf_name}.#{{DOMAIN}}"

        end
        {conf_name}.vm.provider "virtualbox" do |domain,override|
            domain.memory = {memory}
            override.vm.network "private_network",
                                ip: "#{{NETWORK}}.{ipaddr_last_octet}"
            override.vm.hostname = "{conf_name}.#{{DOMAIN}}"
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

    def __init__(self, topology_path, config, num_replicas, num_clients):
        assert isinstance(config, IPAVagrantConfig)
        self.num_replicas = num_replicas
        self.num_clients = num_clients
        self.topology_path = topology_path
        self.config = config

        self.network_octets = '192.168.%s' % random.randint(100, 200)
        self.ip_addrs = self._generate_ip_addresses(self.network_octets,
                                                    constants.IP_ADDR_FIRST)

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

    def _generate_ovirt3_configuration(self):
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

        # each provider requires box but here it is just dummy because we
        # use lab template
        override.vm.box = 'dummy'
        override.vm.box_url = 'https://github.com/myoung34/vagrant-ovirt3/'\\
                              'blob/master/example_box/dummy.box?raw=true'
    end
"""
        config = self.config.ovirt3

        api_user = config['api']['user']
        api_password = config['api']['password']
        api_url = config['api']['url']
        vm_user = config['vm']['user']
        vm_ssh_private_key = config['vm']['ssh_private_key']
        lab_datacenter = config['lab']['datacenter']
        lab_cluster = config['lab']['cluster']

        with open(os.path.join(self.topology_path, config_name), 'w') as f:
            f.write(USER_CONFIG_TEMPLATE.format(
                api_user=api_user,
                api_password=api_password, api_url=api_url,
                vm_user=vm_user, vm_ssh_private_key=vm_ssh_private_key,
                lab_datacenter=lab_datacenter, lab_cluster=lab_cluster))

        return OVIRT_PROVIDER_CONFIG_TEMPLATE.format(ovirt_config=config_name)

    def _generate_provider_specific_images(self):
        PROVIDER_IMAGES_OVERRIDE_TEMPLATE = """
    config.vm.provider "{provider}" do |domain, override|
{overrides}
    end
"""
        PROVIDER_IMAGES_OVERRIDE_LINE_TEMPLATE = "\t\t{key} = \"{value}\"\n"
        images = ""
        for provider in constants.box_mapping[self.config.box]:
            overrides = ""
            for key in constants.box_mapping[self.config.box][provider]:
                overrides += PROVIDER_IMAGES_OVERRIDE_LINE_TEMPLATE.format(
                    key=key,
                    value=constants.box_mapping[
                        self.config.box][provider][key],
                )
            images += PROVIDER_IMAGES_OVERRIDE_TEMPLATE.format(
                provider=provider,
                overrides=overrides,
            )
        return images

    def _shell_generate_install_basic_pkgs(self):
        content = [
            "sudo dnf clean all",
            # upgrade dnf to fix it
            "sudo dnf upgrade dnf* --best --allowerasing -y",
            "sudo dnf config-manager --set-enabled updates-testing"
        ]

        # enable copr repos
        content.extend([
            "sudo dnf copr enable {copr} -y".format(copr=copr)
            for copr in (self.config.required_copr_repos +
                         self.config.copr_repos)
        ])

        # upgrade and install local RPMs
        content.extend([
            "sudo dnf upgrade --best --allowerasing -y",
            (
                '[ "$(ls -A /vagrant/{rpmdir})" ] && '
                'sudo dnf install /vagrant/{rpmdir}/*.rpm --best '
                '--allowerasing -y'.format(rpmdir=constants.RPMS_DIR)
            ),
        ])

        packages = self.config.required_packages + self.config.packages
        if packages:
            content.append(
                "sudo dnf install {} --best --allowerasing -y".format(
                    " ".join(packages))
            )
        return content

    def _shell_generate_resolv_file(self):
        ip_addresses = self.ip_addrs
        content = [
            "sudo echo 'search {}' > /etc/resolv.conf".format(
                self.config.domain),
            "sudo echo 'nameserver {}' >> /etc/resolv.conf".format(
                ip_addresses['master']['ip'])
        ]

        for value in ip_addresses['replicas'].values():
            content.append(
                "sudo echo 'nameserver {}' >> /etc/resolv.conf".format(
                    value['ip'])
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
                    domain=self.config.domain,
                ),
            )

        for t in ['replicas', 'clients']:
            for n, v in ip_addresses[t].items():
                content.append(
                    "sudo echo '{ip} {name}.{domain}' >> /etc/hosts".format(
                        ip=v['ip'],
                        name=n,
                        domain=self.config.domain,
                    ),
                )

        return content

    def _shell_set_hostname(self, hostname):
        if not hostname.endswith(self.config.domain):
            hostname = '{h}.{d}'.format(h=hostname, d=self.config.domain)

        return [
            "sudo hostnamectl set-hostname {}".format(hostname)
        ]

    def _shell_generate_enable_haveged(self):
        config = [
            "sudo dnf install haveged -y",
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
            "sudo cat '/vagrant/{sshpub}' >> /root/.ssh/authorized_keys".
            format(sshpub=constants.CONTROLLER_SSH_PUB_KEY),
        ]
        return content

    def _shell_generate_cp_controller_key(self):
        content = self._shell_generate_create_root_ssh_dir() + [
            "sudo cp /vagrant/{sshpriv} /root/.ssh/id_rsa".format(
                sshpriv=constants.CONTROLLER_SSH_KEY)
        ]
        return content

    def _shell_generate_setenforce(self):
        content = [
            "sudo setenforce %s" % (
                '1' if self.config.selinux_enforcing else '0'),
        ]
        return content

    def generate_vagrant_file(self):
        timestamp = time.time()
        shell_basic_conf = []
        shell_basic_conf.extend(self._shell_generate_setenforce())
        shell_basic_conf.extend(self._shell_generate_install_basic_pkgs())
        shell_basic_conf.extend(self._shell_generate_enable_haveged())
        shell_basic_conf.extend(self._shell_generate_hosts_file())
        shell_basic_conf.extend(self._shell_generate_resolv_file())

        controller = self.BOX_TEMPLATE.format(
            conf_name="controller",
            ipaddr_last_octet=self.ip_addrs['controller']['last_octet'],
            primary_machine=", primary: true",
            memory=self.config.memory_controller,
            time=timestamp,
            shell='\n'.join(shell_basic_conf +
                            self._shell_generate_cp_controller_key() +
                            self._shell_set_hostname('controller'))
        )

        master = self.BOX_TEMPLATE.format(
            conf_name="master",
            ipaddr_last_octet=self.ip_addrs['master']['last_octet'],
            primary_machine="",
            memory=self.config.memory_server,
            time=timestamp,
            shell='\n'.join(
                shell_basic_conf +
                self._shell_generate_add_controller_key_to_athorized() +
                self._shell_set_hostname('master'))
        )

        replicas_conf = []
        for name, addr in self.ip_addrs['replicas'].items():
            replica = self.BOX_TEMPLATE.format(
                conf_name=name,
                ipaddr_last_octet=addr['last_octet'],
                primary_machine="",
                memory=self.config.memory_server,
                time=timestamp,
                shell='\n'.join(
                    shell_basic_conf +
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
                memory=self.config.memory_client,
                time=timestamp,
                shell='\n'.join(
                    shell_basic_conf +
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

        provider_specific_images = self._generate_provider_specific_images()
        providers_config = ''
        providers_config += self._generate_ovirt3_configuration()
        prefix = pwd.getpwuid(os.getuid()).pw_name

        return self.CONFIG_TEMPLATE.format(
            vm_name_prefix=prefix,
            providers=providers_config,
            images=provider_specific_images,
            network=self.network_octets,
            domain=self.config.domain,
            boxes=boxes_conf_export,
        )

    def export_ci_config_file(self,
                              path,
                              ad_admin_name,
                              ad_admin_password,
                              admin_name,
                              admin_password,
                              debug,
                              dirman_dn,
                              dirman_password,
                              dns_forwarder,
                              nis_domain,
                              ntp_server,
                              root_ssh_key_filename,
                              test_dir,
                              domain_level):
        config = dict()
        config['ad_admin_name'] = ad_admin_name
        config['ad_admin_password'] = ad_admin_password
        config['admin_name'] = admin_name
        config['admin_password'] = admin_password
        config['debug'] = debug
        config['dirman_dn'] = dirman_dn
        config['dirman_password'] = dirman_password
        config['dns_forwarder'] = dns_forwarder
        config['nis_domain'] = nis_domain
        config['ntp_server'] = ntp_server
        config['root_ssh_key_filename'] = root_ssh_key_filename
        config['test_dir'] = test_dir
        if domain_level != constants.AUTO_DOMAIN_LEVEL:
            config['domain_level'] = domain_level

        hosts = []
        master = {
            'name': "{}.{}".format('master', self.config.domain),
            'external_hostname': "{}.{}".format('master', self.config.domain),
            'ip': self.ip_addrs['master']['ip'],
            'role': "master",
        }
        hosts.append(master)

        for key, role in [('replicas', 'replica'), ('clients', 'client')]:
            for name, addr in self.ip_addrs[key].items():
                hosts.append({
                    'name': "{}.{}".format(name, self.config.domain),
                    'external_hostname': "{}.{}".format(name,
                                                        self.config.domain),
                    'ip': addr['ip'],
                    'role': role,
                })

        domains = [{
            'name': self.config.domain,
            'type': "IPA",
            'hosts': hosts,
        }]

        config['domains'] = domains

        with io.open(path, 'w') as f:
            yaml.safe_dump(config, f, default_flow_style=False)
            f.flush()
            f.close()


class VagrantCtl(object):
    """Class for Vagrant controls: starting,halting destroying, etc..
    """
    def __init__(self, path):
        self.path = path

    def up(self, output_stream=None):
        p = subprocess.Popen(
            ['vagrant', 'up'],
            cwd=self.path,
            stderr=output_stream,
            stdout=output_stream
        )
        p.wait()

    def halt(self, output_stream=None):
        p = subprocess.Popen(
            ['vagrant', 'halt'],
            cwd=self.path,
            stderr=output_stream,
            stdout=output_stream
        )
        p.wait()

    def destroy(self, output_stream=None):
        p = subprocess.Popen(
            ['vagrant', 'destroy'],
            cwd=self.path,
            stderr=output_stream,
            stdout=output_stream
        )
        p.wait()

    def get_ssh_config(self):
        p = subprocess.Popen(
            ['vagrant', 'ssh-config'],
            cwd=self.path,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        try:
            outs, errs = p.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            p.kill()
            raise RuntimeError("Timeout during 'vagrant ssh-config'")
        else:
            if p.returncode is not None and p.returncode != 0:
                raise RuntimeError("Failed 'vagrant ssh-config': %s" %
                                   errs.decode(sys.stderr.encoding))

            if errs:
                logging.error(errs.decode(sys.stderr.encoding))

            logging.debug("vagrant ssh-config:\n%s", outs.decode(
                sys.stdout.encoding))
            return outs.decode(sys.stdout.encoding)
