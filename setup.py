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
    0: "unsigned",
    8: "rsasha256",
    10: "rsasha512",
    13: "ecdsa256",
    14: "ecdsa384",
    15: "ed25519",
    16: "ed448",
    17: "falcon512",
    18: "dilithium2",
    19: "sphincs+-sha256-128s",
    21404: "xmssmt-sha256-h40-4",
    21408: "xmssmt-sha256-h40-8",
}
ALGORITHMS_PDNS_TO_BIND = {
    "unsigned": "UNSIGNED",
    "rsasha256": "RSASHA256",
    "rsasha512": "RSASHA512", "ecdsa256": "ECDSA256",
    "ecdsa384": "ECDSA384", "ed25519": "ED25519",
    "ed448": "ED448", "falcon512": "FALCON512",
    "dilithium2": "DILITHIUM2", "sphincs+-sha256-128s": "SPHINCS+-SHA256-128S",
    "xmssmt-sha256-h40-4": "XMSSMT_SHA256_H40_4",
    "xmssmt-sha256-h40-8": "XMSSMT_SHA256_H40_8",
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

def pdns_recursor_append(buf: str, file: str):
    stdout, _ = run(("docker-compose", "exec", "-T", "pdns-recursor") + ("sh", "-c", "echo '' >> '{file}'".format(buf=buf, file=file)))
    print(stdout)
    stdout, _ = run(("docker-compose", "exec", "-T", "pdns-recursor") + ("sh", "-c", "echo '{buf}' >> '{file}'".format(buf=buf, file=file)))
    print(stdout)

def pdns_recursor_read(file: str) -> str:
    stdout, _ = run(("docker-compose", "exec", "-T", "pdns-recursor") + ("sh", "-c", "cat '{file}'".format(file=file)))
    return stdout

def pdns_add_zone(name: dns.name.Name, algorithm: str, zone_ip4_set: Set[str], zone_ip6_set: Set[str], nsec: int = 1):
    assert nsec in {1, 3}
    pdns_auth("create-zone", name.to_text())
    if algorithm != "unsigned" and nsec == 3:
        pdns_auth("set-nsec3", name.to_text(), '1 0 0 -', 'narrow')
    if not zone_ip4_set and not zone_ip6_set:
        raise ValueError(f"no ip addresses specified for {name}")
    for subname in ["@"]:
        if zone_ip4_set:
            for zone_ip4 in zone_ip4_set:
                pdns_auth("add-record", name.to_text(), subname, "A", zone_ip4)
        if zone_ip6_set:
            for zone_ip6 in zone_ip6_set:
                pdns_auth("add-record", name.to_text(), subname, "AAAA", zone_ip6)
        pdns_auth("add-record", name.to_text(), subname, "TXT",
             "\"PQC-DNSSEC PoC; details: github.com/desec-io/pqc-dnssec\"")
    if algorithm == "unsigned":
        pass
    elif algorithm.startswith('rsa'):
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
    if not subname.to_text().startswith("unsigned"):
        ds_set = pdns_get_ds(zone)
        for ds in ds_set:
            pdns_auth('add-record', parent.to_text(), subname.to_text(), 'DS', ds.to_text())


def pdns_delegate_desec(zone: dns.name.Name, parent: dns.name.Name, ns_ip4_set: Set[str], ns_ip6_set: Set[str]):
    ns = _pdns_delegate_set_ns_records(zone, parent, ns_ip4_set, ns_ip6_set)
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
            'records': [rr.to_text() for rr in pdns_get_ds(zone)],
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

def bind9_forward_global(name: dns.name.Name) -> dns.name.Name:
    bind9_recursor_append("zone \"{zone_name}\" {{\n\ttype forward;\n\tforward only;\n\t forwarders {{ 172.20.53.103; }};\n}};\n".format(zone_name=name), "/usr/local/etc/named.conf")
    return dns.name.Name(("ns",)) + name

def bind9_delegate_desec(zone: dns.name.Name, parent: dns.name.Name, ns_ip4_set: Set[str], ns_ip6_set: Set[str], ds_set):
    ns = bind9_forward_global(zone)
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
            'records': [rr.to_text() for rr in ds_set],
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
    pdns_add_zone(parent, DEFAULT_ALGORITHM, ns_ip4_set, ns_ip6_set)

    for nsec in [1, 3]:
        for algorithm in SUPPORTED_ALGORITHMS.values():
            zone_name = algorithm
            if algorithm == "sphincs+-sha256-128s":
                zone_name = "sphincs-sha256-128s"
            classic_name = dns.name.Name((zone_name + ('3' if nsec == 3 else ''),)) + parent
            pdns_add_zone(classic_name, algorithm, ns_ip4_set, ns_ip6_set, nsec)
            pdns_delegate_auth(classic_name, parent, ns_ip4_set, ns_ip6_set)

def pdns_setup():
    local_name = dns.name.Name(("pdns", ""))
    local_ns_ip4 = "172.20.53.101"
    pdns_add_test_setup(local_name, {local_ns_ip4}, set())
    pdns_set_trustanchor_recursor(local_name)

    global_name = os.environ.get('DESEC_DOMAIN')
    if global_name:
        global_parent = dns.name.from_text(global_name)
        global_name = dns.name.Name(("pdns",)) + global_parent
        global_ns_ip4_set = set(filter(bool, os.environ.get('PUBLIC_IP4_ADDRESSES', '').split(',')))
        global_ns_ip6_set = set(filter(bool, os.environ.get('PUBLIC_IP6_ADDRESSES', '').split(',')))
        if not global_ns_ip4_set and not global_ns_ip6_set:
            raise ValueError("At least one public IP address needs ot be supplied.")
        pdns_add_test_setup(global_name, global_ns_ip4_set, global_ns_ip6_set)
        conf = pdns_recursor_read("/etc/powerdns/recursor.d/recursor.conf")
        forward_string = "forward-zones+={}={}".format(global_name.to_text(), local_ns_ip4)
        if forward_string in conf:
            print("WARNING: forward_string is already in recursor.conf... ignoring it for now")
        else:
            pdns_recursor_append("forward-zones+={}={}".format(global_name.to_text(), local_ns_ip4), "/etc/powerdns/recursor.d/recursor.conf")
            pdns_recursor("reload-zones")
        pdns_delegate_desec(global_name, global_parent, global_ns_ip4_set, global_ns_ip6_set)

    pdns_auth('rectify-all-zones')

def bind9_add_zone(name: dns.name.Name, algorithm: str, zone_ip4_set: Set[str], zone_ip6_set: Set[str]) -> dns.zone.Zone:
    zone = dns.zone.Zone(origin=name)
    soa = zone.find_node(name, create=True).find_rdataset(IN, SOA, create=True)
    soa.add(dns.rdtypes.ANY.SOA.SOA(IN, SOA, dns.name.Name(("ns",)) + name, dns.name.Name(("jason", "goertzen", "sandboxaq", "com",)), 2023120401, 3600, 600, 604800, 3600), 3600)
    if not zone_ip4_set and not zone_ip6_set:
        raise ValueError(f"no ip addresses specified for {name}")
    for subname in ["@"]:
        node = zone.find_node(subname, create=True)
        if zone_ip4_set:
            a_records = node.find_rdataset(IN, A, create=True)
            for zone_ip4 in zone_ip4_set:
                a_records.add(dns.rdtypes.IN.A.A(IN, A, zone_ip4), 3600)
        if zone_ip6_set:
            aaaa_records = node.find_rdataset(IN, AAAA, create=True)
            for zone_ip6 in zone_ip6_set:
                aaaa_records.add(dns.rdtypes.IN.AAAA.AAAA(IN, AAAA, zone_ip6), 3600)
        text_records = node.find_rdataset(IN, TXT, create=True)
        text_records.add(dns.rdtypes.ANY.TXT.TXT(IN, TXT, "PQC-DNSSEC PoC; details: github.com/desec-io/pqc-dnssec"), 3600)
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
        a_records.add(dns.rdtypes.IN.A.A(IN, A, ns_ip4), 3600)
    aaaa_records = node.find_rdataset(IN, AAAA, create=True)
    for ns_ip6 in ns_ip6_set:
        aaaa_records.add(dns.rdtypes.IN.AAAA.AAAA(IN, AAAA, ns_ip6), 3600)
    if parent is not None:
        parent_node = parent.find_node(ns.to_text(), create=True)
        parent_a_records = parent_node.find_rdataset(IN, A, create=True)
        for ns_ip4 in ns_ip4_set:
            parent_a_records.add(dns.rdtypes.IN.A.A(IN, A, ns_ip4), 3600)
        parent_aaaa_records = node.find_rdataset(IN, AAAA, create=True)
        for ns_ip6 in ns_ip6_set:
            parent_aaaa_records.add(dns.rdtypes.IN.AAAA.AAAA(IN, AAAA, ns_ip6), 3600)
    
    node = zone.find_node(zone_name.to_text(), create=True)
    ns_records = node.find_rdataset(IN, NS, create=True)
    ns_records.add(dns.rdtypes.ANY.NS.NS(IN, NS, ns.to_text()), 3600)
    return ns

def bind9_auth(*args) -> str:
    stdout, _ = run(("docker-compose", "exec", "-T", "bind-auth") + args)
    return stdout

def bind9_auth_append(buf: str, file: str):
    bind9_auth("sh", "-c", "echo '' >> '{file}'".format(buf=buf, file=file))
    bind9_auth("sh", "-c", "echo '{buf}' >> '{file}'".format(buf=buf, file=file))

def bind9_auth_clobber(buf: str, file: str):
    bind9_auth("sh", "-c", "echo '{buf}' > '{file}'".format(buf=buf, file=file))

def bind9_auth_read(file: str) -> str:
    return bind9_auth("sh", "-c", "cat {file}".format(file=file))

def bind9_recursor(*args) -> str:
    stdout, _ = run(("docker-compose", "exec", "-T", "bind-recursor") + args)
    return stdout

def bind9_recursor_clobber(buf: str, file: str):
    bind9_recursor("sh", "-c", "echo '{buf}' > '{file}'".format(buf=buf, file=file))

def bind9_recursor_append(buf: str, file: str):
    bind9_recursor("sh", "-c", "echo '' >> '{file}'".format(buf=buf, file=file))
    bind9_recursor("sh", "-c", "echo '{buf}' >> '{file}'".format(buf=buf, file=file))

def bind9_recursor_read(file: str) -> str:
    return bind9_recursor("sh", "-c", "cat {file}".format(file=file))

def _bind9_generate_keys(zone: dns.zone.Zone, algorithm: str, nsec = 1):
    assert nsec in [1, 3]
    if nsec == 3:
        if algorithm == "RSASHA1":
            algorithm = "NSEC3RSASHA1"
        if algorithm.startswith("RSA"):
            bind9_auth("dnssec-keygen", "-3", "-a", algorithm, "-b", "2048", "-f", "KSK", "-K", "/var/cache/bind/", zone.origin.to_text())
            ds_set = bind9_get_ds(zone.origin)
            bind9_auth("dnssec-keygen", "-3", "-a", algorithm, "-b", "2048", "-K", "/var/cache/bind/", zone.origin.to_text())
        else:
            bind9_auth("dnssec-keygen", "-3", "-a", algorithm, "-f", "KSK", "-K", "/var/cache/bind/", zone.origin.to_text())
            ds_set = bind9_get_ds(zone.origin)
            bind9_auth("dnssec-keygen", "-3", "-a", algorithm, "-K", "/var/cache/bind/", zone.origin.to_text())
    else:
        if algorithm.startswith("RSA"):
            bind9_auth("dnssec-keygen", "-a", algorithm, "-b", "2048", "-f", "KSK", "-K", "/var/cache/bind/", zone.origin.to_text())
            ds_set = bind9_get_ds(zone.origin)
            bind9_auth("dnssec-keygen", "-a", algorithm, "-b", "2048", "-K", "/var/cache/bind/", zone.origin.to_text())
        else:
            bind9_auth("dnssec-keygen", "-a", algorithm, "-f", "KSK", "-K", "/var/cache/bind/", zone.origin.to_text())
            ds_set = bind9_get_ds(zone.origin)
            bind9_auth("dnssec-keygen", "-a", algorithm, "-K", "/var/cache/bind/", zone.origin.to_text())
    print(ds_set)
    return ds_set

def _bind9_zone_string(zone: dns.zone.Zone, dnssecpolicy: str) -> str:
    zone_name = zone.origin.to_text()
    if zone_name.startswith("unsigned"):
        return "zone \"{zone_name}\" IN {{\n    type master;\n    file \"/var/cache/bind/db.{zone_name}\";\n}};".format(zone_name=zone_name)
    else:
        return "zone \"{zone_name}\" IN {{\n    type master;\n    file \"/var/cache/bind/db.{zone_name}\";\n    dnssec-policy \"{dnssecpolicy}\";\n    inline-signing yes;\n}};".format(zone_name=zone_name, dnssecpolicy=dnssecpolicy)

def _bind9_dnssecpolicy_string(algorithm: str, nsec) -> str:
    if (algorithm, nsec) in _bind9_dnssecpolicy_string.seen:
        return ""
    _bind9_dnssecpolicy_string.seen.append((algorithm, nsec))
    return """

dnssec-policy "%(algorithm)s%(nsec)s" {
    keys {
        ksk lifetime unlimited algorithm %(algorithm)s;
        zsk lifetime unlimited algorithm %(algorithm)s;
    };%(nsec3)s
};
""" % {
        'algorithm': algorithm,
        'nsec': nsec,
        'nsec3': '\n    nsec3param iterations 0 optout false salt-length 0;' if nsec == 3 else '',
    }
_bind9_dnssecpolicy_string.seen = []

def bind9_install_zone(zone: dns.zone.Zone, algorithm: str, nsec = 1):
    ds_set = None
    bind9_auth_clobber(zone.to_text(relativize=False), "/var/cache/bind/db.{}".format(zone.origin.to_text()))
    algorithm = ALGORITHMS_PDNS_TO_BIND[algorithm]
    if algorithm != "UNSIGNED":
        ds_set = _bind9_generate_keys(zone, algorithm, nsec)
        bind9_auth_append(_bind9_dnssecpolicy_string(algorithm, nsec), "/usr/local/etc/named.conf")
    bind9_auth_append(_bind9_zone_string(zone, algorithm + str(nsec)), "/usr/local/etc/named.conf")
    return ds_set

def bind9_get_ds(zone: dns.name.Name) -> dns.rdtypes.ANY.DS.DS:
    def remove_prefix(s, prefix):
        return s[s.startswith(prefix) and len(prefix):]


    bind9_lines = bind9_auth("sh", "-c", "dnssec-dsfromkey /var/cache/bind/K{}+*.key".format(zone.to_text())).splitlines()
    ds_texts = [
        # remove extra information from dnssec-dsformkey output
        remove_prefix(
            remove_prefix(
                remove_prefix(
                    line,
                    zone.to_text()  # first remove the name
                ).lstrip(),
                'IN',  # then remove the IN
            ).lstrip(),
            'DS'  # then remove the DS
        ).lstrip().split(';')[0].strip()  # then remove the trailing comment
        for line in bind9_lines
    ]
    try:
        return dns.rrset.from_text_list(zone.to_text(), 0, IN, DS, ds_texts)
    except dns.exception.SyntaxError:
        n = '\n'
        logging.debug(f"Could not obtain DS records for {zone.origin.to_text()}. "
                      f"bind output was \n\n{n.join(bind9_lines)}\n\ndnspython input was\n\n{n.join(ds_texts)}")
        raise

def bind9_install_ds(zone: dns.zone.Zone, parent: dns.zone.Zone, ds: dns.rdtypes.ANY.DS.DS):
    node = parent.find_node(zone.origin.to_text(), create=True)
    ds_records = node.find_rdataset(IN, DS, create=True)
    ds_records.add(ds, 3600)

def bind9_delegate_auth(zone: dns.zone.Zone, parent: dns.zone.Zone, ns_ip4_set: Set[str], ns_ip6_set: Set[str], algorithm: str, nsec = 1):
    zone_name = zone.origin
    parent_name = parent.origin
    ns = _bind9_delegate_set_ns_records(zone, parent, ns_ip4_set, ns_ip6_set)
    subname = zone_name - parent_name
    node = parent.find_node(zone_name.to_text(), create=True)
    ns_records = node.find_rdataset(IN, NS, create=True)
    ns_records.add(dns.rdtypes.ANY.NS.NS(IN, NS, ns.to_text()), 3600)
    ds_set = bind9_install_zone(zone, algorithm, nsec)
    if not subname.to_text().startswith("unsigned"):
        if not ds_set:
            raise Exception("Failed to find DS records")
        for ds in ds_set:
            bind9_install_ds(zone, parent, ds)

def bind9_set_trustanchor_recursor(zone: dns.zone.Zone, ds_set):
    named_conf = bind9_recursor_read("/usr/local/etc/named.conf").splitlines()
    named_conf = named_conf[:-1]
    for ds in ds_set:
        ds_str = "{} static-ds {} {} {} \"{}\";".format(zone.origin.to_text(), ds.key_tag, ds.algorithm, ds.digest_type, binascii.hexlify(ds.digest).decode('utf-8'))
        named_conf.append("    {}".format(ds_str))
    named_conf.append("};")
    named_conf = "\n".join(named_conf)
    bind9_recursor_clobber(named_conf, "/usr/local/etc/named.conf")


def bind9_add_test_setup(parent: dns.name.Name, ns_ip4_set: Set[str], ns_ip6_set: Set[str]) -> dns.zone.Zone:
    parent_zone = bind9_add_zone(parent, DEFAULT_ALGORITHM, ns_ip4_set, ns_ip6_set)
    subzones = dict()
    for nsec in [1, 3]:
        for algorithm in SUPPORTED_ALGORITHMS.values():
            zone_name = algorithm
            if algorithm == "sphincs+-sha256-128s":
                zone_name = "sphincs-sha256-128s"
            classic_name = dns.name.Name((zone_name + ('3' if nsec == 3 else ''),)) + parent
            subzones[classic_name] = bind9_add_zone(classic_name, algorithm, ns_ip4_set, ns_ip6_set)
            bind9_delegate_auth(subzones[classic_name], parent_zone, ns_ip4_set, ns_ip6_set, algorithm, nsec)
    _bind9_delegate_set_ns_records(parent_zone, None, ns_ip4_set, ns_ip6_set)
    ds_set = bind9_install_zone(parent_zone, DEFAULT_ALGORITHM)
    return parent_zone, ds_set

def bind9_setup():
    local_name = dns.name.Name(("bind9", ""))
    local_ns_ip4 = "172.20.53.103"
    local_zone, ds_set = bind9_add_test_setup(local_name, {local_ns_ip4}, set())
    bind9_set_trustanchor_recursor(local_zone, ds_set)
    
    global_name = os.environ.get('DESEC_DOMAIN')
    if global_name:
        global_parent = dns.name.from_text(global_name)
        global_name = dns.name.Name(("bind9",)) + global_parent
        global_ns_ip4_set = set(filter(bool, os.environ.get('PUBLIC_IP4_ADDRESSES', '').split(',')))
        global_ns_ip6_set = set(filter(bool, os.environ.get('PUBLIC_IP6_ADDRESSES', '').split(',')))
        if not global_ns_ip4_set and not global_ns_ip6_set:
            raise ValueError("At least one public IP address needs ot be supplied.")
        _, ds_set = bind9_add_test_setup(global_name, global_ns_ip4_set, global_ns_ip6_set)
        bind9_delegate_desec(global_name, global_parent, global_ns_ip4_set, global_ns_ip6_set, ds_set)
    bind9_auth("rndc", "reconfig")
    bind9_recursor("rndc", "reconfig")


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    parser = argparse.ArgumentParser(description="Script for setting up BIND9 and PowerDNS.")
    parser.add_argument('--bind9', action='store_true', help='Run BIND9 setup')
    parser.add_argument('--pdns', action='store_true', help='Run PowerDNS setup')
    
    args = parser.parse_args()

    if (not args.bind9 and not args.pdns) or args.pdns:
        pdns_setup()
    if args.bind9:
        bind9_setup()
