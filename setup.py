#!/usr/bin/python3
# Author: Martin Basti
# See LICENSE file for license

from setuptools import setup

setup(name='ipa-vagrant-devel-tools',
      version='0.3',
      description='Useful scripts for creating test and delopment environment for IPA',
      author='Martin Basti',
      author_email='martin.basti@gmail.com',
      url='https://github.com/bastiak/ipa-devel-tools',
      packages=['ipavagrant'],
      scripts=['ipa-vagrant-ci-runner', 'ipa-vagrant-ci-topology-create'],
      install_requires=['PyYAML', 'paramiko'],
     )
