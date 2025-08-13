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

import pytest  # type: ignore[import]
from cmk.agent_based.v2 import (
    Result,
    Service,
    State,
    Metric,
)
from cmk_addons.plugins.postfwd.agent_based import postfwd


def get_value_store():
    return {}


def get_rate(_value_store, _key, _time, value: float, *args, **argv):
    return value


EXAMPLE_STRINGTABLE_RULES = [
    ['Rule   0: id->"OK_DNSWL"; action->"DUNNO"; rbl->"=;list.dnswl.org/^127/43200"'],
    ['Rule   1: id->"SET_HELO"; action->"set(HIT_helo=1)"; helo_name->"=;!!, =;[0-9.-]{7}"'],
    ['Rule   2: id->"SET_NODNS"; action->"set(HIT_nodns=1)"; client_name->"=;^unknown$"'],
    ['Rule   3: id->"REJECT_HELO_NODNS"; action->"REJECT Blocked - contact postmaster@example.net for help - Suspicious HELO [$$helo_name] and missing reverse DNS [$$client_address]"; HIT_nodns->"==;1"; HIT_helo->"==;1"'],
    ['Rule   4: id->"REJECT_RBL_ZEN"; action->"REJECT Blocked - contact postmaster@example.net for help - zen.spamhaus.org RBL"; rbl->"=;zen.spamhaus.org"'],
    ['Rule   5: id->"EVAL_DNSBLS"; action->"set(HIT_rbls=$$rblcount)"; rblcount->"all"; rbl->"=;bl.spamcop.net, =;dnsbl-1.uceprotect.net, =;dnsbl-2.uceprotect.net, =;dnsbl-3.uceprotect.net, =;psbl.surriel.com, =;combined.njabl.org, =;dnsbl.ahbl.org, =;dnsbl.sorbs.net, =;ix.dnsbl.manitu.net, =;dyna.spamrats.com"'],
    ['Rule   6: id->"REJECT_RBL_MULTI"; action->"REJECT Blocked - contact postmaster@example.net for help - Multiple DNSBLs"; HIT_rbls->"=>;2"'],
    ['Rule   7: id->"EVAL_RHSBLS"; action->"set(HIT_rhsbls=$$rhsblcount)"; rhsblcount->"all"; rhsbl_sender->"=;multi.uribl.com, =;multi.surbl.org, =;bulk.rhs.mailpolice.com, =;rhsbl.ahbl.org, =;rhsbl.sorbs.net, =;dsn.rfc-ignorant.org"; rhsbl_reverse_client->"=;dynamic.rhs.mailpolice.com"'],
    ['Rule   8: id->"REJECT_RHSBL_MULTI"; action->"REJECT Blocked - contact postmaster@example.net for help - Multiple RHSBLs"; HIT_rhsbls->"=>;2"'],
    ['Rule   9: id->"REJECT_RBL_RHSBL"; action->"REJECT Blocked - contact postmaster@example.net for help - RHSBL and DNSBL"; HIT_rhsbls->"=>;1"; HIT_rbls->"=>;1"'],
    ['Rule  10: id->"REJECT_RBL_HELO"; action->"REJECT Blocked - contact postmaster@example.net for help - DNSBL and suspicious HELO [$$helo_name]"; HIT_rbls->"=>;1"; HIT_helo->"==;1"'],
    ['Rule  11: id->"REJECT_RBL_NODNS"; action->"REJECT Blocked - contact postmaster@example.net for help - DNSBL and missing reverse DNS [$$client_address]"; HIT_rbls->"=>;1"; HIT_nodns->"==;1"'],
    ['Rule  12: id->"REJECT_RHSBL_HELO"; action->"REJECT Blocked - contact postmaster@example.net for help - RHSBL and suspicious HELO [$$helo_name]"; HIT_rhsbls->"=>;1"; HIT_helo->"==;1"'],
    ['Rule  13: id->"REJECT_RHSBL_NODNS"; action->"REJECT Blocked - contact postmaster@example.net for help - RHSBL and missing reverse DNS [$$client_address]"; HIT_rhsbls->"=>;1"; HIT_nodns->"==;1"'],
    ['Rule  14: id->"GREY_HELO"; action->"check_postgrey"; HIT_helo->"==;1"'],
    ['Rule  15: id->"GREY_NODNS"; action->"check_postgrey"; HIT_nodns->"==;1"'],
    ['Rule  16: id->"GREY_RBL"; action->"check_postgrey"; HIT_rbls->"=>;1"'],
    ['Rule  17: id->"GREY_RHSBL"; action->"check_postgrey"; HIT_rhsbls->"=>;1"'],
]
EXAMPLE_SECTION_RULES = [
    'OK_DNSWL', 'SET_HELO', 'SET_NODNS',
    'REJECT_HELO_NODNS', 'REJECT_RBL_ZEN', 'EVAL_DNSBLS', 'REJECT_RBL_MULTI', 'EVAL_RHSBLS',
    'REJECT_RHSBL_MULTI', 'REJECT_RBL_RHSBL', 'REJECT_RBL_HELO', 'REJECT_RBL_NODNS', 'REJECT_RHSBL_HELO', 'REJECT_RHSBL_NODNS',
    'GREY_HELO', 'GREY_NODNS', 'GREY_RBL', 'GREY_RHSBL',
]

EXAMPLE_STRINGTABLE_STATS = [
    ['[STATS] postfwd2::cache 1.35: 4 queries since 0 days, 18:35:35 hours'],
    ['[STATS] Requests: 0.0/min last, 0.0/min overall, 0.0/min top'],
    ['[STATS] Hitrates: 0.0% requests, 0.0% dns, 0.0% rates'],
    ['[STATS] Contents: rate=2'],
    [''],
    ['[STATS] postfwd2::policy 1.35: 4 requests since 0 days, 18:35:35 hours'],
    ['[STATS] Requests: 0.00/min last, 0.00/min overall, 0.20/min top'],
    ['[STATS] Dnsstats: 0.00/min last, 0.00/min overall, 0.00/min top'],
    ['[STATS] Hitrates: 100.0% ruleset, 0.0% parent, 0.0% child, 0.0% rates'],
    ['[STATS] Timeouts: 0.0% (0 of 0 dns queries)'],
    ['[STATS]   4 matches for id:  OK_DNSWL'],
    ['[STATS]   4 matches for id:  SET_HELO'],
]
EXAMPLE_SECTION_STATS = {'OK_DNSWL': 4, 'SET_HELO': 4}


def test_parse_postfwd_rules():
    assert postfwd.parse_postfwd_rules(EXAMPLE_STRINGTABLE_RULES) == EXAMPLE_SECTION_RULES


def test_parse_postfwd_stats():
    assert postfwd.parse_postfwd_stats(EXAMPLE_STRINGTABLE_STATS) == EXAMPLE_SECTION_STATS


@pytest.mark.parametrize('section_rules, section_stats, result', [
    ([], [], []),
    (EXAMPLE_SECTION_RULES, EXAMPLE_SECTION_STATS, [Service(item=id) for id in EXAMPLE_SECTION_RULES]),
])
def test_discovery_postfwd_rule(section_rules, section_stats, result):
    assert list(postfwd.discovery_postfwd_rule(section_rules, section_stats)) == result


@pytest.mark.parametrize('item, params, section_rules, section_stats, result', [
    ('FOO', {}, [], {}, [Result(state=State.UNKNOWN, summary='Rule with id FOO not found')]),
    ('OK_DNSWL', {}, EXAMPLE_SECTION_RULES, EXAMPLE_SECTION_STATS, [
        Result(state=State.OK, summary='OK_DNSWL: 4.0/s'),
        Metric('rate', 4.0, boundaries=(0.0, None)),
    ]),
    ('OK_DNSWL', {'upper': ('fixed', (10, 20))}, EXAMPLE_SECTION_RULES, EXAMPLE_SECTION_STATS, [
        Result(state=State.OK, summary='OK_DNSWL: 4.0/s'),
        Metric('rate', 4.0, levels=(10.0, 20.0), boundaries=(0.0, None)),
    ]),
    ('OK_DNSWL', {'upper': ('fixed', (1, 20))}, EXAMPLE_SECTION_RULES, EXAMPLE_SECTION_STATS, [
        Result(state=State.WARN, summary='OK_DNSWL: 4.0/s (warn/crit at 1.0/s/20.0/s)'),
        Metric('rate', 4.0, levels=(1.0, 20.0), boundaries=(0.0, None)),
    ]),
    ('OK_DNSWL', {'upper': ('fixed', (1, 2))}, EXAMPLE_SECTION_RULES, EXAMPLE_SECTION_STATS, [
        Result(state=State.CRIT, summary='OK_DNSWL: 4.0/s (warn/crit at 1.0/s/2.0/s)'),
        Metric('rate', 4.0, levels=(1.0, 2.0), boundaries=(0.0, None)),
    ]),
    ('REJECT_RBL_NODNS', {}, EXAMPLE_SECTION_RULES, EXAMPLE_SECTION_STATS, [
        Result(state=State.OK, summary='REJECT_RBL_NODNS: 0.0/s'),
        Metric('rate', 0.0, boundaries=(0.0, None)),
    ]),
])
def test_check_postfwd_rule(monkeypatch, item, params, section_rules, section_stats, result):
    monkeypatch.setattr(postfwd, 'get_value_store', get_value_store)
    monkeypatch.setattr(postfwd, 'get_rate', get_rate)
    assert list(postfwd.check_postfwd_rule(item, params, section_rules, section_stats)) == result
