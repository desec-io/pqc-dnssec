import json
import logging
import os
import subprocess
import argparse
from typing import Set, Tuple
import binascii


import dns.dnssec
import dns.name
import dns.rrset
import requests
from dns.rdtypes.IN import *
from dns.rdtypes.ANY import *
# requirements: dnspython, requests
IN = dns.rdataclass.from_text("IN")
SOA = dns.rdatatype.from_text("SOA")
A = dns.rdatatype.from_text("A")
AAAA = dns.rdatatype.from_text("AAAA")
TXT = dns.rdatatype.from_text("TXT")
DS = dns.rdatatype.from_text("DS")
NS = dns.rdatatype.from_text("NS")
DEFAULT_ALGORITHM = "ecdsa256"
SUPPORTED_ALGORITHMS = {
    5: "rsasha1", 8: "rsasha256", 10: "rsasha512",  # pdns also supports 7: "rsasha1-nsec3-sha1",
    13: "ecdsa256", 14: "ecdsa384",
    15: "ed25519", 16: "ed448",
    17: "falcon",
}
ALGORITHMS_PDNS_TO_BIND = {
    "rsasha1": "RSASHA1", "rsasha256": "RSASHA256",
    "rsasha512": "RSASHA256", "ecdsa256": "ECDSA256",
    "ecdsa384": "ECDSA384", "ed25519": "ED25519",
    "ed448": "ED448", "falcon": "FALCON512",
}

def run(args, stdin: str = None) -> Tuple[str, str]:
    logging.debug(f"Running {args}")
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, input=stdin)
    logging.info(f"stdout: {result.stdout}")
    if result.stderr!= "":
        logging.warning(f"stderr: {result.stderr}")
    return result.stdout, result.stderr


def pdns_auth(*args) -> str:
    stdout, _ = run(("docker-compose", "exec", "-T", "pdns-auth", "pdnsutil") + args)
    return stdout


def pdns_recursor(*args) -> str:
    stdout, _ = run(("docker-compose", "exec", "-T", "pdns-recursor", "rec_control") + args)
    return stdout


def pdns_add_zone(name: dns.name.Name, algorithm: str, nsec: int = 1):
    assert nsec in {1, 3}
    pdns_auth("create-zone", name.to_text())
    if nsec == 3:
        pdns_auth("set-nsec3", name.to_text(), '1 0 0 -', 'narrow')
    for subname in ["@", "*"]:
        pdns_auth("add-record", name.to_text(), subname, "A", "127.0.0.1")
        pdns_auth("add-record", name.to_text(), subname, "A", "127.0.0.2")
        pdns_auth("add-record", name.to_text(), subname, "AAAA", "::1")
        pdns_auth("add-record", name.to_text(), subname, "TXT",
             "\"FALCON DNSSEQ PoC; details: github.com/nils-wisiol/dns-falcon\"")
    if algorithm.startswith('rsa'):
        pdns_auth("add-zone-key", name.to_text(), "2048", "active", algorithm)
    else:
        pdns_auth("add-zone-key", name.to_text(), "active", algorithm)


def pdns_get_ds(name: dns.name.Name):
    def remove_prefix(s, prefix):
        return s[s.startswith(prefix) and len(prefix):]

    pdns_lines = pdns_auth("export-zone-ds", name.to_text()).strip().split("\n")
    ds_texts = [
        # remove extra information from pdnsutil output
        remove_prefix(
            remove_prefix(
                remove_prefix(
                    line,
                    name.to_text()  # first remove the name
                ).lstrip(),
                'IN',  # then remove the IN
            ).lstrip(),
            'DS'  # then remove the DS
        ).lstrip().split(';')[0].strip()  # then remove the trailing comment
        for line in pdns_lines
    ]

    try:
        return dns.rrset.from_text_list(name, 0, IN, DS, ds_texts)
    except dns.exception.SyntaxError:
        n = '\n'
        logging.debug(f"Could not obtain DS records for {name.to_text()}. "
                      f"pdns output was \n\n{n.join(pdns_lines)}\n\ndnspython input was\n\n{n.join(ds_texts)}")
        raise


def pdns_set_trustanchor_recursor(name: dns.name.Name):
    ds_set = pdns_get_ds(name)
    for ds in ds_set:
        pdns_recursor("add-ta", name.to_text(), ds.to_text())


def _pdns_delegate_set_ns_records(zone: dns.name.Name, parent: dns.name.Name, ns_ip4_set: Set[str], ns_ip6_set: Set[str]):
    if not zone.is_subdomain(parent):
        raise ValueError(f"Given zone {zone} is not a subdomain of given parent {parent}.")
    subname = zone - parent
    ns = dns.name.Name(('ns',)) + subname + parent
    for ns_ip4 in ns_ip4_set:
        pdns_auth('add-record', zone.to_text(), 'ns', 'A', ns_ip4)
    for ns_ip6 in ns_ip6_set:
        pdns_auth('add-record', zone.to_text(), 'ns', 'AAAA', ns_ip6)
    pdns_auth('add-record', zone.to_text(), '@', 'NS', ns.to_text())
    return ns


def pdns_delegate_auth(zone: dns.name.Name, parent: dns.name.Name, ns_ip4_set: Set[str], ns_ip6_set: Set[str]):
    ns = _pdns_delegate_set_ns_records(zone, parent, ns_ip4_set, ns_ip6_set)
    subname = zone - parent
    pdns_auth('add-record', parent.to_text(), subname.to_text(), 'NS', ns.to_text())
    ds_set = pdns_get_ds(zone)
    for ds in ds_set:
        pdns_auth('add-record', parent.to_text(), subname.to_text(), 'DS', ds.to_text())


def delegate_desec(zone: dns.name.Name, parent: dns.name.Name, ns_ip4_set: Set[str], ns_ip6_set: Set[str]):
    ns = _delegate_set_ns_records(zone, parent, ns_ip4_set, ns_ip6_set)
    data = json.dumps([
        {
            'subname': (ns - parent).to_text(),
            'ttl': 60,
            'type': 'A',
            'records': list(ns_ip4_set),
        },
        {
            'subname': (ns - parent).to_text(),
            'ttl': 60,
            'type': 'AAAA',
            'records': list(ns_ip6_set),
        },
        {
            'subname': (zone - parent).to_text(),
            'ttl': 60,
            'type': 'NS',
            'records': [ns.to_text()],
        },
        {
            'subname': (zone - parent).to_text(),
            'ttl': 60,
            'type': 'DS',
            'records': [rr.to_text() for rr in get_ds(zone)],
        },
    ], indent=4)
    logging.debug(f"Sending to deSEC:\n\n{data}\n\n")
    response = requests.patch(
        url=f"https://desec.io/api/v1/domains/{parent.to_text().rstrip('.')}/rrsets/",
        headers={
            'Authorization': f'Token {os.environ["DESEC_TOKEN"]}',
            'Content-Type': 'application/json',
        },
        data=data
    )
    if response.status_code not in {200, 201, 204}:
        raise Exception(f"Unexpected response with code {response.status_code}: {response.content}")


def pdns_add_test_setup(parent: dns.name.Name, ns_ip4_set: Set[str], ns_ip6_set: Set[str]):
    pdns_add_zone(parent, DEFAULT_ALGORITHM)

    for nsec in [1, 3]:
        for algorithm in SUPPORTED_ALGORITHMS.values():
            classic_example = dns.name.Name((algorithm + ('3' if nsec == 3 else ''),)) + parent
            pdns_add_zone(classic_example, algorithm, nsec)
            pdns_delegate_auth(classic_example, parent, ns_ip4_set, ns_ip6_set)

def pdns_setup():
    local_example = dns.name.Name(("example", ""))
    local_ns_ip4 = "172.20.53.101"
    pdns_add_test_setup(local_example, {local_ns_ip4}, set())
    pdns_set_trustanchor_recursor(local_example)

    global_name = os.environ.get('DESEC_DOMAIN')
    if global_name:
        global_parent = dns.name.from_text(global_name)
        global_example = dns.name.Name(("example",)) + global_parent
        global_ns_ip4_set = set(filter(bool, os.environ.get('PUBLIC_IP4_ADDRESSES', '').split(',')))
        global_ns_ip6_set = set(filter(bool, os.environ.get('PUBLIC_IP6_ADDRESSES', '').split(',')))
        if not global_ns_ip4_set and not global_ns_ip6_set:
            raise ValueError("At least one public IP address needs ot be supplied.")
        pdns_add_test_setup(global_example, global_ns_ip4_set, global_ns_ip6_set)
        pdns_delegate_desec(global_example, global_parent, global_ns_ip4_set, global_ns_ip6_set)

    pdns_auth('rectify-all-zones')

def bind9_add_zone(name: dns.name.Name, algorithm: str) -> dns.zone.Zone:
    zone = dns.zone.Zone(origin=name)
    soa = zone.find_node(name, create=True).find_rdataset(IN, SOA, create=True)
    soa.add(dns.rdtypes.ANY.SOA.SOA(IN, SOA, dns.name.Name(("ns",)) + name, dns.name.Name(("jason", "goertzen", "sandboxaq", "com",)), 2023120401, 3600, 600, 604800, 3600))
    for subname in ["@", "*"]:
        node = zone.find_node(subname, create=True)
        a_records = node.find_rdataset(IN, A, create=True)
        a_records.add(dns.rdtypes.IN.A.A(IN, A, "127.0.0.1"))
        a_records.add(dns.rdtypes.IN.A.A(IN, A, "127.0.0.2"))
        aaaa_records = node.find_rdataset(IN, AAAA, create=True)
        aaaa_records.add(dns.rdtypes.IN.AAAA.AAAA(IN, AAAA, "::1"))
        text_records = node.find_rdataset(IN, TXT, create=True)
        text_records.add(dns.rdtypes.ANY.TXT.TXT(IN, TXT, "FALCON DNSSEQ PoC; details: github.com/nils-wisiol/dns-falcon"))
    return zone

def _bind9_delegate_set_ns_records(zone: dns.zone.Zone, parent: dns.zone.Zone, ns_ip4_set: Set[str], ns_ip6_set: Set[str]):
    zone_name = zone.origin
    if parent is not None and not zone_name.is_subdomain(parent.origin):
        raise ValueError(f"Given zone {zone} is not a subdomain of given parent {parent}.")
    if parent is not None:
        subname = zone_name - parent.origin
    else:
        subname = zone_name
    ns = dns.name.Name(('ns',)) + zone_name
    node = zone.find_node(ns.to_text(), create=True)
    a_records = node.find_rdataset(IN, A, create=True)
    for ns_ip4 in ns_ip4_set:
        a_records.add(dns.rdtypes.IN.A.A(IN, A, ns_ip4))
    aaaa_records = node.find_rdataset(IN, AAAA, create=True)
    for ns_ip6 in ns_ip6_set:
        aaaa_records.add(dns.rdtypes.IN.AAAA.AAAA(IN, AAAA, ns_ip6))
    if parent is not None:
        parent_node = parent.find_node(ns.to_text(), create=True)
        parent_a_records = parent_node.find_rdataset(IN, A, create=True)
        for ns_ip4 in ns_ip4_set:
            parent_a_records.add(dns.rdtypes.IN.A.A(IN, A, ns_ip4))
        parent_aaaa_records = node.find_rdataset(IN, AAAA, create=True)
        for ns_ip6 in ns_ip6_set:
            parent_aaaa_records.add(dns.rdtypes.IN.AAAA.AAAA(IN, AAAA, ns_ip6))
    
    node = zone.find_node(zone_name.to_text(), create=True)
    ns_records = node.find_rdataset(IN, NS, create=True)
    ns_records.add(dns.rdtypes.ANY.NS.NS(IN, NS, ns.to_text()))
    return ns

def bind9_auth(*args) -> str:
    stdout, _ = run(("docker-compose", "exec", "-T", "bind-auth") + args)
    return stdout

def bind9_auth_append(buf: str, file: str):
    bind9_auth("sh", "-c", "echo '' >> '{file}'".format(buf=buf, file=file))
    bind9_auth("sh", "-c", "echo '{buf}' >> '{file}'".format(buf=buf, file=file))

def bind9_auth_write(buf: str, file: str):
    bind9_auth("sh", "-c", "echo '{buf}' > '{file}'".format(buf=buf, file=file))

def bind9_auth_read(file: str) -> str:
    return bind9_auth("sh", "-c", "cat {file}".format(file=file))

def bind9_resolver(*args) -> str:
    stdout, _ = run(("docker-compose", "exec", "-T", "bind-resolver") + args)
    return stdout

def bind9_resolver_clobber(buf: str, file: str):
    bind9_resolver("sh", "-c", "echo '{buf}' > '{file}'".format(buf=buf, file=file))

def bind9_resolver_read(file: str) -> str:
    return bind9_resolver("sh", "-c", "cat {file}".format(file=file))

def _bind9_generate_keys(zone: dns.zone.Zone, algorithm: str):
    algorithm = ALGORITHMS_PDNS_TO_BIND[algorithm]
    if algorithm.startswith("RSA"):
        bind9_auth("dnssec-keygen", "-a", algorithm, "-b", "2048", "-n", "ZONE", "-K", "/usr/local/etc/bind/", zone.origin.to_text())
        bind9_auth("sh", "-c", "mv /usr/local/etc/bind/K{zone}*.key '/usr/local/etc/bind/{zone}key'".format(zone=zone.origin.to_text()))
        bind9_auth("sh", "-c", "mv /usr/local/etc/bind/K{zone}*.private '/usr/local/etc/bind/{zone}private'".format(zone=zone.origin.to_text()))
        bind9_auth("dnssec-keygen", "-a", algorithm, "-b", "2048", "-n", "ZONE", "-f", "KSK", "-K", "/usr/local/etc/bind/", zone.origin.to_text())
        bind9_auth("sh", "-c", "mv /usr/local/etc/bind/K{zone}*.key '/usr/local/etc/bind/KSK_{zone}key'".format(zone=zone.origin.to_text()))
        bind9_auth("sh", "-c", "mv /usr/local/etc/bind/K{zone}*.private '/usr/local/etc/bind/KSK_{zone}private'".format(zone=zone.origin.to_text()))
    else:
        bind9_auth("dnssec-keygen", "-a", algorithm, "-n", "ZONE", "-K", "/usr/local/etc/bind/", zone.origin.to_text())
        bind9_auth("sh", "-c", "mv /usr/local/etc/bind/K{zone}*.key '/usr/local/etc/bind/{zone}key'".format(zone=zone.origin.to_text()))
        bind9_auth("sh", "-c", "mv /usr/local/etc/bind/K{zone}*.private '/usr/local/etc/bind/{zone}private'".format(zone=zone.origin.to_text()))
        bind9_auth("dnssec-keygen", "-a", algorithm, "-n", "ZONE", "-f", "KSK", "-K", "/usr/local/etc/bind/", zone.origin.to_text())
        bind9_auth("sh", "-c", "mv /usr/local/etc/bind/K{zone}*.key '/usr/local/etc/bind/KSK_{zone}key'".format(zone=zone.origin.to_text()))
        bind9_auth("sh", "-c", "mv /usr/local/etc/bind/K{zone}*.private '/usr/local/etc/bind/KSK_{zone}private'".format(zone=zone.origin.to_text()))

def _bind9_sign_zone(zone: dns.zone.Zone, nsec = 1):
    if nsec == 3:
        bind9_auth("dnssec-signzone", "-a", "-o", zone.origin.to_text(), "-N", "INCREMENT", "-t", "-S", "-3", "-f", "/usr/local/etc/bind/db.{}signed".format(zone.origin.to_text()),  "/usr/local/etc/bin/db.{}".format(zone.origin.to_text()), "/usr/local/etc/bind/{}key".format(zone.origin.to_text()), "/usr/local/etc/bind/KSK_{}key".format(zone.origin.to_text()))
    else:
        bind9_auth("dnssec-signzone", "-a", "-o", zone.origin.to_text(), "-N", "INCREMENT", "-t", "-S", "-f", "/usr/local/etc/bind/db.{}signed".format(zone.origin.to_text()), "/usr/local/etc/bind/db.{}".format(zone.origin.to_text()), "/usr/local/etc/bind/{}key".format(zone.origin.to_text()), "/usr/local/etc/bind/KSK_{}key".format(zone.origin.to_text()))


def _bind9_install_named_string(zone: dns.zone.Zone) -> str:
    zone_name = zone.origin.to_text()
    return "zone \"{zone_name}\" IN {{\n    type master;\n    file \"/usr/local/etc/bind/db.{zone_name}signed\";\n}};".format(zone_name=zone_name)

def bind9_install_zone(zone: dns.zone.Zone, algorithm: str, nsec = 1):
    bind9_auth_write(zone.to_text(relativize=False), "/usr/local/etc/bind/db.{}".format(zone.origin.to_text()))
    _bind9_generate_keys(zone, algorithm)
    _bind9_sign_zone(zone, nsec)
    bind9_auth_append(_bind9_install_named_string(zone), "/usr/local/etc/named.conf")

def bind9_get_ds(zone: dns.zone.Zone) -> dns.rdtypes.ANY.DS.DS:
    def remove_prefix(s, prefix):
        return s[s.startswith(prefix) and len(prefix):]


    bind9_lines = bind9_auth("dnssec-dsfromkey", "/usr/local/etc/bind/KSK_{}".format(zone.origin.to_text()[:-1])).splitlines()
    ds_texts = [
        # remove extra information from dnssec-dsformkey output
        remove_prefix(
            remove_prefix(
                remove_prefix(
                    line,
                    zone.origin.to_text()  # first remove the name
                ).lstrip(),
                'IN',  # then remove the IN
            ).lstrip(),
            'DS'  # then remove the DS
        ).lstrip().split(';')[0].strip()  # then remove the trailing comment
        for line in bind9_lines
    ]
    try:
        return dns.rrset.from_text_list(zone.origin.to_text(), 0, IN, DS, ds_texts)
    except dns.exception.SyntaxError:
        n = '\n'
        logging.debug(f"Could not obtain DS records for {zone.origin.to_text()}. "
                      f"bind output was \n\n{n.join(bind9_lines)}\n\ndnspython input was\n\n{n.join(ds_texts)}")
        raise

def bind9_install_ds(zone: dns.zone.Zone, parent: dns.zone.Zone, ds: dns.rdtypes.ANY.DS.DS):
    node = parent.find_node(zone.origin.to_text(), create=True)
    ds_records = node.find_rdataset(IN, DS, create=True)
    ds_records.add(ds)

def bind9_delegate_auth(zone: dns.zone.Zone, parent: dns.zone.Zone, ns_ip4_set: Set[str], ns_ip6_set: Set[str], algorithm: str, nsec = 1):
    zone_name = zone.origin
    parent_name = parent.origin
    ns = _bind9_delegate_set_ns_records(zone, parent, ns_ip4_set, ns_ip6_set)
    subname = zone_name - parent_name
    node = parent.find_node(zone_name.to_text(), create=True)
    ns_records = node.find_rdataset(IN, NS, create=True)
    ns_records.add(dns.rdtypes.ANY.NS.NS(IN, NS, ns.to_text()))
    bind9_install_zone(zone, algorithm, nsec)
    ds_set = bind9_get_ds(zone)
    if not ds_set:
        raise Exception("Failed to find DS records")
    for ds in ds_set:
        bind9_install_ds(zone, parent, ds)

def bind9_set_trustanchor_recursor(zone: dns.zone.Zone):
    ds_set = bind9_get_ds(zone)
    zone_name = zone.origin
    named_conf = bind9_resolver_read("/usr/local/etc/named.conf").splitlines()
    named_conf = named_conf[:-1]
    for ds in ds_set:
        ds_str = "{} static-ds {} {} {} \"{}\";".format(zone.origin.to_text(), ds.key_tag, ds.algorithm, ds.digest_type, binascii.hexlify(ds.digest).decode('utf-8'))
        named_conf.append("    {}".format(ds_str))
    named_conf.append("};")
    named_conf = "\n".join(named_conf)
    bind9_resolver_clobber(named_conf, "/usr/local/etc/named.conf")


def bind9_add_test_setup(parent: dns.name.Name, ns_ip4_set: Set[str], ns_ip6_set: Set[str]):
    parent_zone = bind9_add_zone(parent, DEFAULT_ALGORITHM)
    subzones = dict()
    for nsec in [1]:
        for algorithm in SUPPORTED_ALGORITHMS.values():
            classic_example = dns.name.Name((algorithm + ('3' if nsec == 3 else ''),)) + parent
            subzones[classic_example] = bind9_add_zone(classic_example, algorithm)
            bind9_delegate_auth(subzones[classic_example], parent_zone, ns_ip4_set, ns_ip6_set, algorithm, nsec)
    _bind9_delegate_set_ns_records(parent_zone, None, ns_ip4_set, ns_ip6_set)
    bind9_install_zone(parent_zone, DEFAULT_ALGORITHM)
    _bind9_sign_zone(parent_zone)
    bind9_set_trustanchor_recursor(parent_zone)

def bind9_setup():
    local_example = dns.name.Name(("example", ""))
    local_ns_ip4 = "172.20.53.101"
    bind9_add_test_setup(local_example, {local_ns_ip4}, set())
    
    global_name = os.environ.get('DESEC_DOMAIN')
    if global_name:
        global_parent = dns.name.from_text(global_name)
        global_example = dns.name.Name(("example",)) + global_parent
        global_ns_ip4_set = set(filter(bool, os.environ.get('PUBLIC_IP4_ADDRESSES', '').split(',')))
        global_ns_ip6_set = set(filter(bool, os.environ.get('PUBLIC_IP6_ADDRESSES', '').split(',')))
        if not global_ns_ip4_set and not global_ns_ip6_set:
            raise ValueError("At least one public IP address needs ot be supplied.")
        bind9_add_test_setup(global_example, global_ns_ip4_set, global_ns_ip6_set)
        delegate_desec(global_example, global_parent, global_ns_ip4_set, global_ns_ip6_set)
    bind9_auth("rndc", "reconfig")
    bind9_resolver("rndc", "reconfig")


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    parser = argparse.ArgumentParser(description="Script for setting up BIND9 and PowerDNS.")
    parser.add_argument('--bind9', action='store_true', help='Run BIND9 setup')
    parser.add_argument('--pdns', action='store_true', help='Run PowerDNS setup')
    
    args = parser.parse_args()

    if (not args.bind9 and not args.powerdns) or args.powerdns:
        pdns_setup()
    if args.bind9:
        bind9_setup()
