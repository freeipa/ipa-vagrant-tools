#!/usr/bin/python3
# Author: Martin Basti
# See LICENSE file for license

import argparse
import logging

from ipavagrant.ipaci import IPACIRunner

def main():
    parser = argparse.ArgumentParser(description="")
    parser.add_argument("test_name", type=str, action="append",
                        help="Name of CI test(s) to be executed")
    # parser.add_argument("--ip-address", dest="ip_address", type=str,
    #                     metavar="IPADDR", required=True,
    #                     help="the ip address of the controller")
    # parser.add_argument("--username", dest="username", type=str,
    #                     default="vagrant", metavar="USER", help="User login "
    #                     "name to connect to controller (default: vagrant)")
    # parser.add_argument("--password", dest="password", type=str,
    #                     default="vagrant", metavar="PASSWD", help="User password "
    #                     "to connect to controller (default: vagrant)")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)

    runner = IPACIRunner(args.test_name)
    runner.run()

if __name__ == "__main__":
    main()
