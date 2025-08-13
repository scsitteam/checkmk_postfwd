#!/usr/bin/env python3
# -*- encoding: utf-8; py-indent-offset: 4 -*-
#
# checkmk_postfwd - Checkmk extension for postfwd
#
# Copyright (C) 2025  Marius Rieder <marius.rieder@scs.ch>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

from pathlib import Path
from typing import TypedDict

from .bakery_api.v1 import (
    FileGenerator,
    OS,
    Plugin,
    PluginConfig,
    register,
    quote_shell_string,
)


class PostFwdConfig(TypedDict, total=False):
    port: int
    file: str


def get_postfwd_plugin_files(conf: PostFwdConfig) -> FileGenerator:
    yield Plugin(
        base_os=OS.LINUX,
        source=Path('postfwd.sh'),
        target=Path('postfwd.sh')
    )

    yield PluginConfig(
        base_os=OS.LINUX,
        lines=_get_linux_cfg_lines(conf.get('port', 10042), conf.get('file', '/etc/postfix/postfwd.cf')),
        target=Path('postfwd.cfg'),
        include_header=True
    )


def _get_linux_cfg_lines(port: int, file: str) -> list[str]:
    # To be loaded with 'source' in Solaris shell script
    return [
        f'PORT={int(port)}',
        f'FILE={quote_shell_string(file)}',
    ]


register.bakery_plugin(
    name='postfwd',
    files_function=get_postfwd_plugin_files,
)
