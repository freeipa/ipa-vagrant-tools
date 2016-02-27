#!/usr/bin/python3
# Author: Martin Basti
# See LICENSE file for license

import os
import shutil
import pytest

from ipavagrant.ipaci import IPACITopology


def test_ipa_vagrant_ci_topology_create_def():
    path = os.path.abspath("test_create_top_1")
    try:
        t = IPACITopology(path)
        t.create()
    finally:
        shutil.rmtree(path, ignore_errors=True)


def test_ipa_vagrant_ci_topology_create_replicas():
    path = os.path.abspath("test_create_top_r1")
    try:
        t = IPACITopology(path, replicas=1)
        t.create()
    finally:
        shutil.rmtree(path, ignore_errors=True)


def test_ipa_vagrant_ci_topology_create_clients():
    path = os.path.abspath("test_create_top_c1")
    try:
        t = IPACITopology(path, clients=1)
        t.create()
    finally:
        shutil.rmtree(path, ignore_errors=True)


def test_ipa_vagrant_ci_topology_create_replicas_clients():
    path = os.path.abspath("test_create_top_r1_c1")
    try:
        t = IPACITopology(path, replicas=1, clients=1)
        t.create()
    finally:
        shutil.rmtree(path, ignore_errors=True)
