#!/usr/bin/python3
# Author: Martin Basti
# See LICENSE file for license


import argparse
import os
import sys
import io
import subprocess

from ipavagrant import constants
from ipavagrant.config import IPAVagrantConfig
from ipavagrant.vagrant import VagrantFile

def create_directories(parent_name):
    os.mkdir(parent_name)
    os.mkdir(os.path.join(parent_name, constants.RPMS_DIR))
    os.mkdir(os.path.join(parent_name, constants.PROVISIONING_DIR))


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
                        default=None, help="Domain for provisioned VM")
    parser.add_argument('--add-package', dest="packages", action="append",
                        help="Allows to specify packages that will be "
                             "installed from repository", default=[],
                        metavar="NAME")
    parser.add_argument('--add-copr', dest="copr_repos", action="append",
                        help="Allows to specify copr repositories that will "
                             "be enabled", default=[],
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

    # selinux
    parser.add_argument('--selinux-enforce', dest="selinux_enforcing",
                        action='store_true',
                        help="Set SELinux to enforce mode")
    parser.add_argument('--no-selinux-enforce', dest="selinux_enforcing",
                        action='store_false',
                        help="Set SELinux to permissive mode")
    parser.set_defaults(selinux_enforcing=None)

    parser.add_argument('--box', dest="box", default=None,
                        help="Set box that will be used")
    parser.add_argument('--config-file', dest="config_file", default=None,
                        help="Path to configuration file (default: %s)" %
                        constants.DEFAULT_CONFIG_FILENAME)
    parser.add_argument('--export-config', dest="export_config", default=False,
                        action="store_true", help="export current "
                        "configuration to config file (destination: "
                        "--config-file)")
    parser.add_argument('--show-config', dest="show_config", default=False,
                        action="store_true", help="show current configuration")

    args = parser.parse_args()

    config = IPAVagrantConfig(
        filename=args.config_file,
        domain=args.domain,
        memory_controller=args.memory_controller,
        memory_server=args.memory_server,
        memory_client=args.memory_client,
        selinux_enforcing=args.selinux_enforcing,
        box=args.box
    )

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
        print("Configuration saved to", where, file=sys.stderr)
        return


    topology_path = os.path.abspath(args.topology_name)
    vagrant_file = VagrantFile(
        config.domain, config.box, topology_path,
        config.memory_controller, config.memory_server,
        config.memory_client, args.replicas, args.clients,
        extra_packages=args.packages,
        extra_copr_repos=args.copr_repos,
        enforcing=config.selinux_enforcing,
        required_packages=config.required_packages,
        required_copr_repos=config.required_copr_repos)

    create_directories(args.topology_name)

    # generate SSH keys for controller
    command = [
        "ssh-keygen",
        "-f", str(os.path.join(args.topology_name,
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

    with io.open(os.path.join(topology_path, constants.VAGRANT_FILE), "w") as f:
        f.write(vagrant_file.generate_vagrant_file())
        f.close()

    vagrant_file.export_ci_config_file(
        os.path.join(args.topology_name, config.ci_config_file),
        config.ipa_ci_ad_admin_name,
        config.ipa_ci_ad_admin_password,
        config.ipa_ci_admin_name,
        config.ipa_ci_admin_password,
        config.ipa_ci_debug,
        config.ipa_ci_dirman_dn,
        config.ipa_ci_dirman_password,
        config.ipa_ci_dns_forwarder,
        config.ipa_ci_nis_domain,
        config.ipa_ci_ntp_server,
        config.ipa_ci_root_ssh_key_filename,
        config.ipa_ci_test_dir)

if __name__ == '__main__':
    try:
        main()
    except RuntimeError as e:
        print(e, file=sys.stderr)
        sys.exit(2)

