#!/usr/bin/python3
# Author: Martin Basti
# See LICENSE file for license

import os
import io
import subprocess

from . import constants
from .config import IPAVagrantConfig
from .vagrant import VagrantFile


class IPACITopology(object):
    """Class for operations with IPA CI topologies in Vagrant
    """

    def __init__(
            self, path, config_file=None, config_options=None,
            replicas=0, clients=0,
            packages=[], copr_repos=[]
        ):
        self.path = path
        if config_options is None:
            config_options = {}
        assert isinstance(config_options, dict)

        self.config = IPAVagrantConfig(
            filename=config_file,
            **config_options
        )

        self.vagrant_file = VagrantFile(
            self.config.domain, self.config.box, path,
            self.config.memory_controller, self.config.memory_server,
            self.config.memory_client, replicas, clients,
            extra_packages=packages,
            extra_copr_repos=copr_repos,
            enforcing=self.config.selinux_enforcing,
            required_packages=self.config.required_packages,
            required_copr_repos=self.config.required_copr_repos)

    def _create_directories(self):
        os.mkdir(self.path)
        os.mkdir(os.path.join(self.path, constants.RPMS_DIR))
        os.mkdir(os.path.join(self.path, constants.PROVISIONING_DIR))

    def create(self):
        self._create_directories()

        # generate SSH keys for controller
        command = [
            "ssh-keygen",
            "-f", str(os.path.join(self.path,
                constants.CONTROLLER_SSH_KEY)),
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

        with io.open(os.path.join(self.path, constants.VAGRANT_FILE), "w") as f:
            f.write(self.vagrant_file.generate_vagrant_file())
            f.close()

        self.vagrant_file.export_ci_config_file(
            os.path.join(self.path, self.config.ci_config_file),
            self.config.ipa_ci_ad_admin_name,
            self.config.ipa_ci_ad_admin_password,
            self.config.ipa_ci_admin_name,
            self.config.ipa_ci_admin_password,
            self.config.ipa_ci_debug,
            self.config.ipa_ci_dirman_dn,
            self.config.ipa_ci_dirman_password,
            self.config.ipa_ci_dns_forwarder,
            self.config.ipa_ci_nis_domain,
            self.config.ipa_ci_ntp_server,
            self.config.ipa_ci_root_ssh_key_filename,
            self.config.ipa_ci_test_dir)
