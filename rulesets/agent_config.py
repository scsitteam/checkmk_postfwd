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

from cmk.rulesets.v1 import Title
from cmk.rulesets.v1.form_specs import (
    DictElement,
    Dictionary,
    DefaultValue,
    SingleChoice,
    SingleChoiceElement,
    Integer,
    String,
)
from cmk.rulesets.v1.rule_specs import AgentConfig, Topic


def _parameter_form_postfwd_bakery():
    return Dictionary(
        elements={
            'deploy': DictElement(
                parameter_form=SingleChoice(
                    elements=[
                        SingleChoiceElement(name='deploy', title=Title("Deploy the PostFWD plug-in.")),
                        SingleChoiceElement(name='do_not_deploy', title=Title("Do not deploy the PostFWD plug-in.")),
                    ],
                    prefill=DefaultValue('deploy'),
                ),
                required=True,
            ),
            'port': DictElement(
                parameter_form=Integer(
                    title=Title('PostFWD Port'),
                ),
                required=False,
            ),
            'file': DictElement(
                parameter_form=String(
                    title=Title('PostFWD Configfile'),
                ),
                required=False,
            ),
        }
    )


rule_spec_postfwd_bakery = AgentConfig(
    title=Title("PostFWD Agent"),
    name='postfwd',
    parameter_form=_parameter_form_postfwd_bakery,
    topic=Topic.APPLICATIONS,
)
