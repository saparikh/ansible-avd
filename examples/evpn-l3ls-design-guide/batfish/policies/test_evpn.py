from netaddr import *
import os

from .test_utils import record_results, TEST_STATUS_FAIL, TEST_STATUS_PASS

from collections import defaultdict

import pytest
from pybatfish.datamodel import HeaderConstraints


@pytest.fixture(scope="module")
def l2_vnis(bf):
    return bf.q.vxlanVniProperties().answer().frame()


@pytest.fixture(scope="module")
def l3_vnis(bf):
    return bf.q.evpnL3VniProperties().answer().frame()


@pytest.fixture(scope="module")
def node_props(bf):
    return bf.q.nodeProperties().answer().frame()


def test_dns_servers(bf,node_props):
    """Ensure all nodes have DNS servers configured."""
    expected = {'192.168.2.1', '8.8.8.8'}

    bf.asserts.current_assertion = 'Assert all routers have correct DNS Servers'
    try:
        assert(all(node_props.DNS_Servers.map(lambda x: set(x) == expected)))
        record_results(bf, status=TEST_STATUS_PASS, message='All routers have correct DNS Servers\n')

    except Exception as e:
        df = node_props[node_props.DNS_Servers != expected][
             ['Node', 'DNS_Servers']]
        record_results(bf, status=TEST_STATUS_FAIL,
                                  message=f"Misconfigured DNS Servers\n{df}")
        raise e


def test_ntp_servers(bf,node_props):
    bf.asserts.current_assertion = 'Assert all routers have correct NTP Servers'
    """Ensure all nodes have NTP servers configured."""
    expected = {'0.north-america.pool.ntp.org', '1.north-america.pool.ntp.org'}


    try:
        assert(all(node_props.NTP_Servers.map(lambda x: set(x) == expected)))
        record_results(bf, status=TEST_STATUS_PASS, message='All routers have correct NTP Servers\n')

    except Exception as e:
        df = node_props[node_props.NTP_Servers != expected][
             ['Node', 'NTP_Servers']]
        record_results(bf, status=TEST_STATUS_FAIL,
                                  message=f"Misconfigured NTP Servers\n{df}")
        raise e


def test_bgp_sessions_up(bf):
    """Ensure all bgp sessions are up."""
    bgpsessions = bf.q.bgpSessionStatus().answer().frame()
    not_established = bgpsessions[
        bgpsessions['Established_Status'] != 'ESTABLISHED']
    if not not_established.empty:
        raise AssertionError(
            f"Some BGP sessions are not established:\n{not_established}")


def test_no_l2_vnis_empty_flood_list(bf, l2_vnis):
    """Check in any VNIs have empty flood lists."""

    empty_flood = l2_vnis[(l2_vnis['VLAN'].notnull()) & (
        l2_vnis['VTEP_Flood_List'].apply(lambda x: not x))]
    if not empty_flood.empty:
        df = empty_flood[['Node', 'VRF', 'VNI']]
        raise AssertionError(f"Found VNIs with an empty flood list\n{df}")


def test_vni_to_vrf_mapping_unique(bf, l2_vnis, l3_vnis):
    """Ensure that the VNI mapping is unique across all nodes."""
    # For L2 VNIS
    g = l2_vnis[['VNI', 'VRF', 'Node']].groupby(['VNI', 'Node']).count()
    if not all(g['VRF'] == 1):
        df = g[g["VRF"] != 1]
        raise AssertionError(f"Non unique VNI -> VRF mappings found:\n{df}")

    # For L3 VNIS
    g = l3_vnis[['VNI', 'VRF', 'Node']].groupby(['VNI', 'Node']).count()
    if not all(g['VRF'] == 1):
        df = g[g["VRF"] != 1]
        raise AssertionError(f"Non unique VNI -> VRF mappings found:\n{df}")


def test_l3_vni_rds(bf, l3_vnis):
    bgp_proc = bf.q.bgpProcessConfiguration().answer().frame()[
        ['Node', 'VRF', 'Router_ID']]
    bgp_proc = bgp_proc[bgp_proc.VRF == 'default']
    for _, proc in bgp_proc.iterrows():
        rds = l3_vnis[(l3_vnis.Node == proc.Node)]
        for i, vni in rds.iterrows():
            actual_rd = rds['Route_Distinguisher'][i]
            expected_rd = f"{proc.Router_ID}:{vni.VNI}"
            if actual_rd != expected_rd:
                raise AssertionError(
                    f"Bad route distinguisher. Expected {expected_rd}, got {actual_rd}\n{rds.loc[i]}")


def test_vtep_reachability(bf, l2_vnis):
    """Check that all VTEPs can reach each other."""
    # Collect the list of VTEP_IP from vxlanVniProperties and then loop
    # through to do traceroute
    vtep_ip_list = set(l2_vnis['Local_VTEP_IP'])
    vni_dict = defaultdict(dict)

    for index, row in l2_vnis.iterrows():
        node = row['Node']
        t_ip = row['Local_VTEP_IP']
        vni_dict[node]['Local_IP'] = t_ip
        for vtep_ip in vtep_ip_list:
            if vtep_ip != t_ip:
                try:
                    vni_dict[node]['Remote_IPs'].add(vtep_ip)
                except KeyError:
                    vni_dict[node]['Remote_IPs'] = {vtep_ip}

    for src_location in vni_dict.keys():
        for remote_vtep in vni_dict[src_location]['Remote_IPs']:
            src_ip = vni_dict[src_location]['Local_IP']
            headers = HeaderConstraints(
                srcIps=src_ip, dstIps=remote_vtep,
                ipProtocols='udp', dstPorts='4789')
            tr = bf.q.traceroute(startLocation=src_location + "[@vrf(default)]",
                                 headers=headers).answer().frame()
            for trace in tr.Traces[0]:
                if trace.disposition != 'ACCEPTED':
                    raise AssertionError(
                        f"{src_location}:{src_ip} cannot reach VTEP {remote_vtep}")
