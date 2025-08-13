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

import re
import time

from cmk.agent_based.v2 import (
    AgentSection,
    check_levels,
    CheckPlugin,
    CheckResult,
    DiscoveryResult,
    get_rate,
    get_value_store,
    Result,
    Service,
    State,
    StringTable,
)

rule_pattern = re.compile(r'->"(.*?)"')
rule_stats = re.compile(r'\s(\d+) matches for id:\s+(\S+)')


def parse_postfwd_rules(string_table: StringTable) -> list[str]:
    rules = []
    for rule in string_table:
        mo = rule_pattern.search(rule[0])
        if mo:
            rules.append(mo.group(1))
    return rules


def parse_postfwd_stats(string_table: StringTable) -> dict[str, int]:
    stats = {}
    for rule in string_table:
        mo = rule_stats.search(rule[0])
        print(f"{rule} => {mo}")
        if mo:
            stats[mo.group(2)] = int(mo.group(1))
    return stats


agent_section_postfwd_rules = AgentSection(
    name='postfwd_rules',
    parse_function=parse_postfwd_rules,
)


agent_section_postfwd_stats = AgentSection(
    name='postfwd_stats',
    parse_function=parse_postfwd_stats,
)


def discovery_postfwd_rule(
    section_postfwd_rules: list | None,
    section_postfwd_stats: dict | None,
) -> DiscoveryResult:
    for rule in section_postfwd_rules:
        yield Service(item=rule)


def check_postfwd_rule(
    item: str,
    params: dict,
    section_postfwd_rules: list | None,
    section_postfwd_stats: dict | None,
) -> CheckResult:

    if item not in section_postfwd_rules:
        yield Result(state=State.UNKNOWN, summary=f"Rule with id {item} not found")
        return

    value_store = get_value_store()
    now = time.time()

    value = get_rate(value_store, f"postfwd_rule.{item}".lower(), now, section_postfwd_stats.get(item, 0), raise_overflow=True)

    yield from check_levels(
        value=value,
        levels_upper=params.get('upper', None),
        metric_name='rate',
        render_func=lambda v: "%.1f/s" % v,
        label=item,
        boundaries=(0, None),
    )


check_plugin_opnsense_gateway = CheckPlugin(
    name='postfwd_rule',
    sections=['postfwd_rules', 'postfwd_stats'],
    service_name='PostFWD %s',
    discovery_function=discovery_postfwd_rule,
    check_function=check_postfwd_rule,
    check_default_parameters={},
    check_ruleset_name='postfwd_rule',
)
