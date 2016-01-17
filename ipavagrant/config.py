#!/usr/bin/python3
# Author: Martin Basti
# See LICENSE file for license

import os
import copy
import io
import yaml

from .constants import DEFAULT_CONFIG, DEFAULT_CONFIG_FILENAME


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
