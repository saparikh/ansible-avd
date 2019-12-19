from .test_utils import record_results

from collections import defaultdict
import pandas as pd

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
    bf.asserts.current_assertion = 'Assert all routers have correct DNS Servers'
    expected = {'192.168.2.1', '8.8.8.8'}

    # dataframe of nodes that do not have expected DNS servers
    df = node_props[node_props.DNS_Servers.map(lambda x: set(x) != expected)][
        ['Node', 'DNS_Servers']]

    test = df.empty
    pass_message = "All routers have correct DNS Servers\n"
    fail_message = f"Misconfigured DNS Servers\n{df}"

    record_results(bf, test, pass_message, fail_message)


def test_ntp_servers(bf,node_props):
    """Ensure all nodes have NTP servers configured."""
    bf.asserts.current_assertion = 'Assert all routers have correct NTP Servers'
    expected = {'0.north-america.pool.ntp.org', '1.north-america.pool.ntp.org'}

    # dataframe of nodes that do not have expected DNS servers
    df = node_props[node_props.NTP_Servers.map(lambda x: set(x) != expected)][
        ['Node', 'NTP_Servers']]

    test = df.empty
    pass_message = "All routers have correct NTP Servers\n"
    fail_message = f"Misconfigured NTP Servers\n{df}"

    record_results(bf, test, pass_message, fail_message)


def test_bgp_sessions_up(bf):
    """Ensure all bgp sessions are up."""
    bf.asserts.current_assertion = 'Assert all configured BGP sessions are established'

    bgpsessions = bf.q.bgpSessionStatus().answer().frame()
    not_established = bgpsessions[
        bgpsessions['Established_Status'] != 'ESTABLISHED']

    test = not not_established.empty
    pass_message = 'All BGP sessions are established\n'
    fail_message = f"Some BGP sessions are not established\n{not_established}"

    record_results(bf, test, pass_message, fail_message)


def test_no_l2_vnis_empty_flood_list(bf, l2_vnis):
    """Check in any VNIs have empty flood lists."""
    bf.asserts.current_assertion = 'Assert no L2 VNIs have an empty flood list'

    empty_flood = l2_vnis[(l2_vnis['VLAN'].notnull()) & (
        l2_vnis['VTEP_Flood_List'].apply(lambda x: not x))]
    df = empty_flood[['Node', 'VRF', 'VNI']]

    test = df.empty
    pass_message = 'No L2 VNIs with empty flood list\n'
    fail_message = f"Found L2 VNIs with an empty flood list\n{df}"

    record_results(bf, test, pass_message, fail_message)


def test_l2_vni_to_vrf_mapping_unique(bf, l2_vnis):
    """Ensure that the L2 VNI mapping is unique across all nodes."""
    bf.asserts.current_assertion = 'Assert unique L2 VNI to VRF mapping on each node'

    g = l2_vnis[['VNI', 'VRF', 'Node']].groupby(['VNI', 'Node']).count()

    test = all(g['VRF'] == 1)
    df = g[g["VRF"] != 1]
    pass_message = 'No non-unique VNI -> VRF mappings found on any nodes\n'
    fail_message =f"Non unique VNI -> VRF mappings found:\n{df}"

    record_results(bf, test, pass_message, fail_message)


def test_l3_vni_to_vrf_mapping_unique(bf, l3_vnis):
    """Ensure that the L3 VNI mapping is unique across all nodes."""
    bf.asserts.current_assertion = 'Assert unique L3 VNI to VRF mapping on each node'

    g = l3_vnis[['VNI', 'VRF', 'Node']].groupby(['VNI', 'Node']).count()

    test = all(g['VRF'] == 1)
    df = g[g["VRF"] != 1]
    pass_message = 'No non-unique VNI -> VRF mappings found on any nodes\n'
    fail_message =f"Non unique VNI -> VRF mappings found:\n{df}"

    record_results(bf, test, pass_message, fail_message)

def test_l3_vni_rds(bf, l3_vnis):
    """Ensure that all L3 VNIs use the router-id as the route-distinguisher"""
    bf.asserts.current_assertion = 'Assert all L3 VNIs used router-id as the route-distinguisher'

    bgp_proc = bf.q.bgpProcessConfiguration().answer().frame()[
        ['Node', 'VRF', 'Router_ID']]
    bgp_proc = bgp_proc[bgp_proc.VRF == 'default']

    df = pd.DataFrame()
    index = 0
    for _, proc in bgp_proc.iterrows():
        rds = l3_vnis[(l3_vnis.Node == proc.Node)]
        for i, vni in rds.iterrows():
            actual_rd = rds['Route_Distinguisher'][i]
            expected_rd = f"{proc.Router_ID}:{vni.VNI}"
            if actual_rd != expected_rd:

                df.loc[index] = rds.loc[i]
                index += 1

    test = df.empty
    pass_message = 'All L3 VNIs have properly configured route-distinguisher\n'
    fail_message =f"Found L3 VNIs with incorrect route-distinguisher:\n{df}"

    record_results(bf, test, pass_message, fail_message)


def test_vtep_reachability(bf, l2_vnis):
    """Check that all VTEPs can reach each other."""
    bf.asserts.current_assertion = 'Assert all VTEP reachability'

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

    tr_dict = defaultdict(list)

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
                    tr_dict[f"{src_location}:{src_ip}"].append(remote_vtep)

    test = not len(tr_dict)
    pass_message = 'Full VTEP to VTEP reachability\n'
    fail_message = f"Some VTEPs unable to reach others:\n{dict(tr_dict)}"

    record_results(bf, test, pass_message, fail_message)