#!/usr/bin/python3
# Author: Martin Basti
# See LICENSE file for license

import paramiko  # python3-paramiko
import sys
import time
import argparse

class RunTest(object):
    """
    This allows to configure ssh connection to controller machine and start test.
    """
    def __init__(self, test_name, controller_ip, controller_login="vagrant",
               controller_passwd="vagrant", port=22):

        self.test_name = test_name
        self.controller_ip = controller_ip
        self.controller_login = controller_login
        self.controller_passwd = controller_passwd
        self.port = port

    def print_output(self, session):
        status_ready = False
        while not status_ready:
            time.sleep(0.1)
            status_ready = session.exit_status_ready()
            while session.recv_ready():
                sys.stdout.buffer.write(session.recv(1024))
            while session.recv_stderr_ready():
                sys.stderr.buffer.write(session.recv_stderr(1024))
        sys.stdout.flush()
        sys.stderr.flush()

    def run(self):
        transport = paramiko.Transport((self.controller_ip, self.port))
        transport.connect(
            username=self.controller_login,
            password=self.controller_passwd
        )

        session = transport.open_channel("session")
        session.exec_command(
            "sudo "
            "IPATEST_YAML_CONFIG=/vagrant/ipa-test-config.yaml "
            "ipa-run-tests "
            "{test_name}".format(test_name=self.test_name))
        self.print_output(session)
        sys.stdout.write("EXIT STATUS: {}\n".format(session.recv_exit_status()))
        transport.close()


def main():
    parser = argparse.ArgumentParser(description="")
    parser.add_argument("test_name", type=str, action="append",
                        help="Name of CI test(s) to be executed")
    parser.add_argument("--ip-address", dest="ip_address", type=str,
                        metavar="IPADDR", required=True,
                        help="the ip address of the controller")
    parser.add_argument("--username", dest="username", type=str,
                        default="vagrant", metavar="USER", help="User login "
                        "name to connect to controller (default: vagrant)")
    parser.add_argument("--password", dest="password", type=str,
                        default="vagrant", metavar="PASSWD", help="User password "
                        "to connect to controller (default: vagrant)")
    args = parser.parse_args()

    for testname in args.test_name:
        test = RunTest(
            testname,
            args.ip_address,
            controller_login=args.username,
            controller_passwd=args.password,
            port=22
        )
        test.run()

if __name__ == "__main__":
    main()
