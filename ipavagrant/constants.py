#!/usr/bin/python3
# Author: Martin Basti
# See LICENSE file for license

import os
import pwd


DEFAULT_CONFIG_FILENAME = os.path.expanduser("~/.ipa_vagrant_config.yaml")
DEFAULT_TOPO_CONFIG_FILENAME = os.path.expanduser(
    "~/.ipa_vagrant_topo_config.yaml")

RPMS_DIR = "rpms"
LOGS_DIR = "logs"
IPA_RUNNER_INIT_FILE = ".runner_init.yaml"
PROVISIONING_DIR = "provisioning"
VAGRANT_FILE = "Vagrantfile"
ANSIBLE_FILE = "ansible.yml"
CONTROLLER_SSH_KEY = "controller_rsa"
CONTROLLER_SSH_PUB_KEY = "controller_rsa.pub"
IP_ADDR_FIRST = 100

AUTO_DOMAIN_LEVEL = -1

# please keep ABC order of keys
DEFAULT_CONFIG = dict(
    box="f28",
    ci_config_file="ipa-test-config.yaml",
    domain="ipa.test",
    ipa_ci_ad_admin_name="Administrator",
    ipa_ci_ad_admin_password="Secret123456",
    ipa_ci_admin_name="admin",
    ipa_ci_admin_password="Secret123",
    ipa_ci_debug=False,
    ipa_ci_dirman_dn="cn=Directory Manager",
    ipa_ci_dirman_password="Secret123",
    ipa_ci_dns_forwarder="8.8.8.8",
    ipa_ci_nis_domain="ipatest",
    ipa_ci_ntp_server="1.pool.ntp.org",
    ipa_ci_root_ssh_key_filename="/root/.ssh/id_rsa",
    ipa_ci_test_dir="/root/ipatests",
    ipa_ci_domain_level=AUTO_DOMAIN_LEVEL,
    memory_client=1024,
    memory_controller=1024,
    memory_server=2048,
    required_copr_repos=[
        '"@freeipa/freeipa-master"'],
    required_packages=[
        "vim",
        "PyYAML",
        "bind-dyndb-ldap"],
    selinux_enforcing=False,
    packages=[],  # this is override from CLI
    copr_repos=[],  # this is override from CLI
    ovirt3=dict(
        api=dict(
            user=pwd.getpwuid(os.getuid()).pw_name,
            password="Secret123",
            url="https://example.test:443",
        ),
        vm=dict(
            user=pwd.getpwuid(os.getuid()).pw_name,
            ssh_private_key=os.path.join(pwd.getpwuid(os.getuid()).pw_dir,
                                         ".ssh", "id_rsa")
        ),
        lab=dict(
            datacenter="",
            cluster="",
        ),
    ),
)

box_mapping = {
    "f22": {
        "libvirt": {
            "override.vm.box": "f22",
            "override.vm.box_url": "http://download.fedoraproject.org/pub/"
                                   "fedora/linux/releases/22/Cloud/x86_64/"
                                   "Images/Fedora-Cloud-Base-Vagrant-22-"
                                   "20150521.x86_64.vagrant-libvirt.box",
        },
        "virtualbox": {
            "override.vm.box": "box-cutter/fedora22",
        },
        "ovirt3": {
            "domain.template": "ipa-Fedora-23-x86_64-developer-brq",
        },
    },
    "f23": {
        "libvirt": {
            "override.vm.box": "f23",
            "override.vm.box_url": "http://download.fedoraproject.org/pub/"
                                   "fedora/linux/releases/23/Cloud/x86_64/"
                                   "Images/Fedora-Cloud-Base-Vagrant-23-"
                                   "20151030.x86_64.vagrant-libvirt.box",
        },
        "virtualbox": {
            "override.vm.box": "box-cutter/fedora23",
        },
        "ovirt3": {
            "domain.template": "ipa-Fedora-23-x86_64-developer-brq",
        },
    },
    "f24": {
        "libvirt": {
            "override.vm.box": "f24",
            "override.vm.box_url":
                "http://download.eng.brq.redhat.com/pub/fedora/linux//"
                "development/latest-24/CloudImages/x86_64/images/"
                "Fedora-Cloud-Base-Vagrant-24-20160615.n.0.x86_64."
                "vagrant-libvirt.box",
        },
        "virtualbox": {
            "override.vm.box": "box-cutter/fedora24",
        },
        "ovirt3": {
            "domain.template": "ipa-Fedora-24-x86_64-developer-brq",
        },
    },
    "f25": {
        "libvirt": {
            "override.vm.box": "f25",
            "override.vm.box_url":
                "https://download.fedoraproject.org/pub/fedora/linux/releases/"
                "25/CloudImages/x86_64/images/Fedora-Cloud-Base-Vagrant-25-1.3"
                ".x86_64.vagrant-libvirt.box",
        },
        "virtualbox": {
            "override.vm.box": "box-cutter/fedora25",
        },
        "ovirt3": {
            "domain.template": "ipa-Fedora-24-x86_64-developer-brq",
        },
    },
    "f26": {
        "libvirt": {
            "override.vm.box": "f26",
            "override.vm.box_url":
                "https://download.fedoraproject.org/pub/fedora/linux/releases/"
                "26/CloudImages/x86_64/images/Fedora-Cloud-Base-Vagrant-26-1.5"
                ".x86_64.vagrant-libvirt.box",
        },
        "virtualbox": {
            "override.vm.box": "box-cutter/fedora26",
        },
        "ovirt3": {
            "domain.template": "ipa-Fedora-26-x86_64-developer-brq",
        },
    },
    "f27": {
        "libvirt": {
            "override.vm.box": "f27",
            "override.vm.box_url":
                "https://download.fedoraproject.org/pub/fedora/linux/releases/"
                "27/CloudImages/x86_64/images/Fedora-Cloud-Base-Vagrant-27-1.6"
                ".x86_64.vagrant-libvirt.box",
        },
        "virtualbox": {
            "override.vm.box": "f27",
            "override.vm.box_url":
                "http://download.eng.brq.redhat.com/pub/fedora/linux/releases/"
                "27/CloudImages/x86_64/images/Fedora-Cloud-Base-Vagrant-27-1.6"
                ".x86_64.vagrant-virtualbox.box"
        },
        "ovirt3": {
            "domain.template": "ipa-Fedora-27-x86_64-developer-brq",
        },
    },
    "f28": {
        "libvirt": {
            "override.vm.box": "f28",
            "override.vm.box_url":
                "https://download.fedoraproject.org/pub/fedora/linux/releases/"
                "28/Cloud/x86_64/images/Fedora-Cloud-Base-Vagrant-28-1.1"
                ".x86_64.vagrant-libvirt.box",
        },
        "virtualbox": {
            "override.vm.box": "f28",
            "override.vm.box_url":
                "http://download.eng.brq.redhat.com/pub/fedora/linux/releases/"
                "28/Cloud/x86_64/images/Fedora-Cloud-Base-Vagrant-28-1.1"
                ".x86_64.vagrant-virtualbox.box"
        },
        "ovirt3": {
            "domain.template": "ipa-Fedora-28-x86_64-developer-brq",
        },
    },
}


DEFAULT_TEST_TOPO_CONFIG = {
    'tests': {
        'backup_and_restore': {
            'path': 'test_integration/test_backup_and_restore.py',
            'topology': 'master_only',
        },
        'backup_and_restore_dom0': {
            'path': 'test_integration/test_backup_and_restore.py',
            'topology': 'master_only_dom0',
        },
        'dnssec': {
            'path': 'test_integration/dnssec.py',
            'topology': 'master_2replicas',
        },
        'dnssec_dom0': {
            'path': 'test_integration/dnssec.py',
            'topology': 'master_2replicas_dom0',
        },
        'installation': {
            'path': 'test_integration/test_installation.py',
            'topology': 'master_3replicas',
        },
        'installation_dom0': {
            'path': 'test_integration/test_installation.py',
            'topology': 'master_3replicas_dom0',
        },
        'replication_layouts': {
            'path': 'test_integration/test_replication_layouts.py',
            'topology': 'master_3replicas',
        },
        'replication_layouts_dom0': {
            'path': 'test_integration/test_replication_layouts.py',
            'topology': 'master_3replicas_dom0',
        },
        'simple_replication': {
            'path': 'test_integration/test_simple_replication.py',
            'topology': 'master_2replicas',
        },
        'simple_replication_dom0': {
            'path': 'test_integration/test_simple_replication.py',
            'topology': 'master_2replicas_dom0',
        },
        'topology': {
            'path': 'test_integration/test_topology.py',
            'topology': 'master_2replicas',
        },
        'topology_dom0': {
            'path': 'test_integration/test_topology.py',
            'topology': 'master_2replicas_dom0',
        },
    },

    'topologies': {
        # supported keywords
        # 'topo_name': {
        #     'replicas': 1,
        #     'clients': 2,
        #     'box': 'f23',
        #     'memory_controller': 1024,
        #     'memory_server': 1024,
        #     'memory_client': 1024,
        #     'domain': 'ipa.test',
        #     'copr_repos': ['repo1', 'repo2'],
        #     'packages': ['pkg1', 'pkg2'],
        #     'config_file': '/path/to/config',
        #         ^--------- otherwise default configuration will be used
        # AND any option from DEFAULT_CONFIG
        # }

        '_default_': {
            'replicas': 1,
            'packages': [
                'freeipa-server', 'freeipa-server-dns', 'freeipa-tests',
            ],
        },
        'master_only': {
        },
        'master_only_dom0': {
            'ipa_ci_domain_level': 0,
        },
        'master_replica': {
            'replicas': 1,
        },
        'master_replica_dom0': {
            'replicas': 1,
            'ipa_ci_domain_level': 0,
        },
        'master_2replicas': {
            'replicas': 2,
        },
        'master_2replicas_dom0': {
            'replicas': 2,
            'ipa_ci_domain_level': 0,
        },
        'master_3replicas': {
            'replicas': 3,
        },
        'master_3replicas_dom0': {
            'replicas': 3,
            'ipa_ci_domain_level': 0,
        },
    },
}
