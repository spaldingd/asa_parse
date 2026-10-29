#!/usr/bin/env python3
"""
asa_parse.py - Extract objects and rulebase from a Cisco ASA (8.5) running-config.

Standard library only (Python 3.8+).  See asa_parser_spec.md for the full specification.

Usage:
    python asa_parse.py running-config.txt [-o output] [--format json,csv]
                        [--dm-inline resolve|keep|both] [--expand] [--strict]
    python asa_parse.py --selftest          # run against the embedded sample config

Outputs are written to <output>/<YYYY-MM-DD_HH-MM-SS>/ (a new folder per run, so runs can be
kept and compared; add "output/" to .gitignore):
    asa_model.json, objects.csv, object_members.csv, rules.csv, [rules_expanded.csv]
"""
import argparse
import csv
import ipaddress
import itertools
import json
import os
import re
import sys
from datetime import datetime, timezone

TOOL_VERSION = "0.1.0"

# --------------------------------------------------------------------------- #
# Lookup tables
# --------------------------------------------------------------------------- #
PORTS = {
    "aol": 5190, "bgp": 179, "biff": 512, "bootpc": 68, "bootps": 67, "chargen": 19,
    "cifs": 3020, "citrix-ica": 1494, "cmd": 514, "ctiqbe": 2748, "daytime": 13,
    "discard": 9, "domain": 53, "echo": 7, "exec": 512, "finger": 79, "ftp": 21,
    "ftp-data": 20, "gopher": 70, "h323": 1720, "hostname": 101, "https": 443,
    "ident": 113, "imap4": 143, "irc": 194, "isakmp": 500, "kerberos": 750,
    "klogin": 543, "kshell": 544, "ldap": 389, "ldaps": 636, "login": 513,
    "lotusnotes": 1352, "lpd": 515, "mobile-ip": 434, "nameserver": 42,
    "netbios-dgm": 138, "netbios-ns": 137, "netbios-ssn": 139, "nfs": 2049,
    "nntp": 119, "ntp": 123, "pcanywhere-data": 5631, "pcanywhere-status": 5632,
    "pim-auto-rp": 496, "pop2": 109, "pop3": 110, "pptp": 1723, "radius": 1645,
    "radius-acct": 1646, "rip": 520, "rsh": 514, "rtsp": 554, "secureid-udp": 5510,
    "sip": 5060, "smtp": 25, "snmp": 161, "snmptrap": 162, "sqlnet": 1521, "ssh": 22,
    "sunrpc": 111, "syslog": 514, "tacacs": 49, "talk": 517, "telnet": 23, "tftp": 69,
    "time": 37, "uucp": 540, "vxlan": 4789, "who": 513, "whois": 43, "www": 80,
    "xdmcp": 177,
}
ICMP_TYPES = {
    "echo-reply": 0, "unreachable": 3, "source-quench": 4, "redirect": 5,
    "alternate-address": 6, "echo": 8, "router-advertisement": 9,
    "router-solicitation": 10, "time-exceeded": 11, "parameter-problem": 12,
    "timestamp-request": 13, "timestamp-reply": 14, "information-request": 15,
    "information-reply": 16, "mask-request": 17, "mask-reply": 18,
    "conversion-error": 31, "mobile-redirect": 32,
}
PROTOS = {
    "ip": None, "icmp": 1, "igmp": 2, "ipinip": 4, "tcp": 6, "igrp": 9, "udp": 17,
    "gre": 47, "esp": 50, "ah": 51, "icmp6": 58, "eigrp": 88, "ospf": 89, "nos": 94,
    "pim": 103, "pcp": 108, "snp": 109, "sctp": 132, "tcp-udp": None,
}
PROTO_BY_NUM = {v: k for k, v in PROTOS.items() if v is not None}
OPS = ("eq", "neq", "lt", "gt", "range")
LOG_LEVELS = {"emergencies", "alerts", "critical", "errors", "warnings",
              "notifications", "informational", "debugging",
              "0", "1", "2", "3", "4", "5", "6", "7"}
OPT_KW = {"log", "time-range", "inactive"}
GROUP_NS = {"network", "service", "protocol", "icmp-type", "security", "user"}
KIND_BY_NS = {"network": "network_group", "service": "service_group",
              "protocol": "protocol_group", "icmp-type": "icmp_group",
              "security": "other_group", "user": "other_group"}
DM_RE = re.compile(r"^DM_INLINE_", re.I)
REMARK_RE = re.compile(r"^access-list\s+(\S+)\s+(?:line\s+(\d+)\s+)?remark(?:\s+(.*))?$", re.I)
NAME_RE = re.compile(r"^name\s+(\S+)\s+(\S+)(?:\s+description\s+(.*))?$", re.I)


class ParseError(Exception):
    pass


# Lexical warnings (unknown port/protocol names) are collected with the current line.
_LEX = []
_CUR = [0]


def lex_warn(msg):
    item = (_CUR[0], msg)
    if item not in _LEX:
        _LEX.append(item)


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #
def is_ipv4(t):
    try:
        ipaddress.IPv4Address(t)
        return True
    except ValueError:
        return False


def is_netmask(t):
    if not is_ipv4(t):
        return False
    inv = int(ipaddress.IPv4Address(t)) ^ 0xFFFFFFFF
    return (inv & (inv + 1)) == 0


def is_ipv6_prefix(t):
    if ":" not in t:
        return False
    try:
        ipaddress.IPv6Network(t, strict=False)
        return True
    except ValueError:
        return False


def to_cidr(ip, mask):
    try:
        return str(ipaddress.ip_network("%s/%s" % (ip, mask), strict=False))
    except ValueError:
        return None


def rest_after(line, keyword):
    """Text after the first occurrence of keyword (used for descriptions/remarks)."""
    parts = line.split(None, 1)
    return parts[1].strip() if len(parts) > 1 else ""


def port_num(tok):
    if tok.isdigit():
        return int(tok)
    n = PORTS.get(tok.lower())
    if n is None:
        lex_warn("unknown port name '%s'" % tok)
        return tok
    return n


def proto_info(tok):
    l = tok.lower()
    if l in PROTOS:
        return l, PROTOS[l]
    if l.isdigit():
        n = int(l)
        return PROTO_BY_NUM.get(n, l), n
    lex_warn("unknown protocol name '%s'" % tok)
    return l, None


def parse_port_spec(t, i):
    if i >= len(t) or t[i].lower() not in OPS:
        raise ParseError("expected port operator, got '%s'" % (t[i] if i < len(t) else "<end>"))
    op = t[i].lower()
    if op == "range":
        if i + 2 >= len(t):
            raise ParseError("range needs two ports")
        vals = [port_num(t[i + 1]), port_num(t[i + 2])]
        return {"op": op, "raw": "range %s %s" % (t[i + 1], t[i + 2]), "values": vals}, i + 3
    if i + 1 >= len(t):
        raise ParseError("%s needs a port" % op)
    return {"op": op, "raw": "%s %s" % (op, t[i + 1]), "values": [port_num(t[i + 1])]}, i + 2


def port_text(spec):
    if spec is None:
        return None
    v = spec["values"]
    if spec["op"] == "eq":
        return str(v[0])
    if spec["op"] == "range":
        return "%s-%s" % (v[0], v[1])
    return "%s %s" % (spec["op"], v[0])


def parse_icmp(t, i):
    """type [code] starting at t[i]; returns (dict, new_i)."""
    raw = t[i]
    l = raw.lower()
    num = int(l) if l.isdigit() else ICMP_TYPES.get(l)
    if num is None:
        lex_warn("unknown icmp type '%s'" % raw)
    i += 1
    code = None
    if i < len(t) and t[i].isdigit():
        code = int(t[i])
        i += 1
    return {"raw": raw, "type": num, "code": code}, i


def icmp_text(ic):
    if not ic:
        return None
    txt = ic["raw"]
    if ic.get("code") is not None:
        txt += " code %s" % ic["code"]
    return txt


def mk_tuple(proto, src=None, dst=None, icmp=None, via=None):
    text = proto
    if dst:
        text += "/" + dst
    if src:
        text += " (src %s)" % src
    if icmp:
        text += "/" + icmp
    return {"protocol": proto, "protocol_number": PROTOS.get(proto), "source_ports": src,
            "destination_ports": dst, "icmp": icmp, "text": text, "via": list(via or [])}


def parse_service_tokens(t):
    """Tokens of the form: <proto> [source <op>..] [destination <op>..]  or  icmp [type [code]]."""
    if not t:
        raise ParseError("empty service definition")
    name, num = proto_info(t[0])
    spec = {"protocol": name, "protocol_number": num, "source_port": None,
            "destination_port": None, "icmp": None}
    i = 1
    if name in ("tcp", "udp", "tcp-udp", "sctp"):
        while i < len(t):
            w = t[i].lower()
            if w == "source":
                spec["source_port"], i = parse_port_spec(t, i + 1)
            elif w == "destination":
                spec["destination_port"], i = parse_port_spec(t, i + 1)
            else:
                raise ParseError("unexpected token '%s' in service definition" % t[i])
    elif name in ("icmp", "icmp6") and i < len(t):
        spec["icmp"], i = parse_icmp(t, i)
    return spec


def spec_to_tuples(spec, via):
    protos = ["tcp", "udp"] if spec["protocol"] == "tcp-udp" else [spec["protocol"]]
    return [mk_tuple(p, port_text(spec["source_port"]), port_text(spec["destination_port"]),
                     icmp_text(spec["icmp"]), via) for p in protos]


def net_text(d):
    t = d["type"]
    if t == "subnet":
        return d.get("cidr") or "%s/%s" % (d["value"], d.get("mask"))
    if t == "range":
        return "%s-%s" % (d["start"], d["end"])
    if t == "fqdn":
        return "fqdn:%s" % d["value"]
    if t == "interface":
        return "interface:%s" % d["value"]
    if t == "identity":
        return d["raw"]
    if t in ("any", "any4", "any6"):
        return t
    return d.get("value", "")


def uniq(items):
    seen, out = set(), []
    for x in items:
        if x["text"] not in seen:
            seen.add(x["text"])
            out.append(x)
    return out


def split_blocks(text):
    """Top-level line + its indented children. Returns [(lineno, header, [(lineno, child)])]."""
    blocks, cur = [], None
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip()
        if not line.strip():
            continue
        if line[0] in " \t":
            if cur is not None:
                cur[2].append((n, line.strip()))
            continue
        if line[0] in "!:":
            cur = None
            continue
        cur = (n, line.strip(), [])
        blocks.append(cur)
    return blocks


# --------------------------------------------------------------------------- #
# Parser / model
# --------------------------------------------------------------------------- #
class AsaParser:
    def __init__(self):
        self.hostname = None
        self.version = None
        self.names = {}
        self.objs = {ns: {} for ns in list(GROUP_NS) + ["time-range"]}
        self.acls = {}
        self.bindings = []
        self.warnings = []
        self.unresolved = []
        self._unres_seen = set()
        self.used = set()
        self.unparsed_count = 0

    # ---- diagnostics ------------------------------------------------------- #
    def warn(self, line, msg):
        self.warnings.append({"line": line, "message": msg})

    def unres(self, ns, name, ctx):
        key = (ns, name, ctx)
        if key not in self._unres_seen:
            self._unres_seen.add(key)
            self.unresolved.append({"kind": ns, "name": name, "referenced_from": ctx})

    # ---- top level --------------------------------------------------------- #
    def parse(self, text):
        blocks = split_blocks(text)
        # pass 1: names, objects, groups, time-ranges, hostname/version
        for ln, hdr, kids in blocks:
            _CUR[0] = ln
            t = hdr.split()
            kw = t[0].lower()
            try:
                if kw == "hostname" and len(t) > 1:
                    self.hostname = t[1]
                elif kw == "asa" and len(t) > 2 and t[1].lower() == "version":
                    self.version = t[2]
                elif kw == "name":
                    m = NAME_RE.match(hdr)
                    if m:
                        self.names[m.group(2)] = {"ip": m.group(1), "description": m.group(3) or "",
                                                  "source_line": ln}
                elif kw == "object" and len(t) >= 3 and t[1].lower() in ("network", "service"):
                    self.parse_object(ln, t, kids)
                elif kw == "object-group" and len(t) >= 3 and t[1].lower() in GROUP_NS:
                    self.parse_group(ln, t, kids)
                elif kw == "time-range" and len(t) >= 2:
                    o = self.new_obj("time-range", "time_range", t[1], ln)
                    o["members"] = [{"type": "raw", "text": c} for _, c in kids]
                    self.objs["time-range"][t[1]] = o
            except (ParseError, IndexError, ValueError) as e:
                self.warn(ln, "block '%s': %s" % (hdr[:60], e))

        self.compute_group_views()

        # pass 2: ACLs and access-groups
        for ln, hdr, kids in blocks:
            _CUR[0] = ln
            t = hdr.split()
            kw = t[0].lower()
            try:
                if kw == "access-list" and len(t) >= 3:
                    self.handle_acl_line(ln, hdr)
                elif kw == "access-group" and len(t) >= 3:
                    self.handle_access_group(ln, t)
            except (ParseError, IndexError, ValueError) as e:
                self.warn(ln, "line '%s': %s" % (hdr[:80], e))

        for acl in self.acls.values():
            acl["bound"] = any(b["acl"] == acl["name"] for b in self.bindings)
        for b in self.bindings:
            if b["acl"] not in self.acls:
                self.warn(b["source_line"], "access-group references undefined ACL '%s'" % b["acl"])
        for ln, msg in _LEX:
            self.warn(ln, msg)

    # ---- objects ----------------------------------------------------------- #
    def new_obj(self, ns, kind, name, ln):
        if name in self.objs[ns]:
            self.warn(ln, "duplicate %s '%s' (previous definition overwritten)" % (ns, name))
        return {"name": name, "kind": kind, "ns": ns, "description": "",
                "inline_generated": bool(DM_RE.match(name)), "ptype": None, "value": None,
                "members": [], "members_resolved": None, "embedded_nat_raw": None,
                "source_line": ln, "unparsed_lines": []}

    def alias_ip(self, tok):
        if tok in self.names:
            return self.names[tok]["ip"], tok
        return tok, None

    def net_value(self, a, b=None):
        """Build a network value dict from an address token (+ optional mask)."""
        ip, alias = self.alias_ip(a)
        if b is not None and is_ipv4(ip) and is_netmask(b):
            return {"type": "subnet", "value": ip, "mask": b, "cidr": to_cidr(ip, b), "alias": alias,
                    "raw": "%s %s" % (a, b)}
        if is_ipv6_prefix(ip) and "/" in ip:
            return {"type": "ipv6", "value": ip, "alias": alias, "raw": a}
        if ":" in ip or is_ipv4(ip):
            return {"type": "host", "value": ip, "alias": alias, "raw": a}
        raise ParseError("cannot interpret address '%s'" % a)

    def parse_object(self, ln, t, kids):
        typ, name = t[1].lower(), t[2]
        ns = "network" if typ == "network" else "service"
        o = self.new_obj(ns, "network_object" if typ == "network" else "service_object", name, ln)
        for cl, c in kids:
            _CUR[0] = cl
            ct = c.split()
            k = ct[0].lower()
            try:
                if k == "description":
                    o["description"] = rest_after(c, "description")
                elif k == "nat":
                    o["embedded_nat_raw"] = ((o["embedded_nat_raw"] + "\n") if o["embedded_nat_raw"] else "") + c
                elif typ == "network" and k == "host":
                    o["value"] = self.net_value(ct[1])
                elif typ == "network" and k == "subnet":
                    o["value"] = self.net_value(ct[1], ct[2] if len(ct) > 2 else None)
                    if o["value"]["type"] == "host":   # v4 "subnet" without a valid mask
                        raise ParseError("invalid subnet definition")
                elif typ == "network" and k == "range":
                    o["value"] = {"type": "range", "start": ct[1], "end": ct[2]}
                elif typ == "network" and k == "fqdn":
                    fq = [x for x in ct[1:] if x.lower() not in ("v4", "v6")]
                    o["value"] = {"type": "fqdn", "value": fq[0]}
                elif typ == "service" and k == "service":
                    o["value"] = parse_service_tokens(ct[1:])
                else:
                    raise ParseError("unrecognised child")
            except (ParseError, IndexError) as e:
                o["unparsed_lines"].append(c)
                self.unparsed_count += 1
                self.warn(cl, "object %s '%s': %s: %s" % (typ, name, e, c))
        self.objs[ns][name] = o

    def parse_group(self, ln, t, kids):
        typ, name = t[1].lower(), t[2]
        o = self.new_obj(typ, KIND_BY_NS[typ], name, ln)
        if typ == "service" and len(t) > 3:
            o["ptype"] = t[3].lower()
        for cl, c in kids:
            _CUR[0] = cl
            ct = c.split()
            k = ct[0].lower()
            try:
                if k == "description":
                    o["description"] = rest_after(c, "description")
                elif k == "group-object":
                    o["members"].append({"type": "group", "ref": ct[1]})
                elif typ == "network" and k == "network-object":
                    if ct[1].lower() == "object":
                        o["members"].append({"type": "object", "ref": ct[2]})
                    elif ct[1].lower() == "host":
                        o["members"].append(self.net_value(ct[2]))
                    else:
                        o["members"].append(self.net_value(ct[1], ct[2] if len(ct) > 2 else None))
                elif typ == "service" and k == "port-object":
                    spec, _ = parse_port_spec(ct, 1)
                    o["members"].append({"type": "port", "op": spec["op"], "raw": spec["raw"],
                                         "values": spec["values"], "text": port_text(spec)})
                elif typ == "service" and k == "service-object":
                    if ct[1].lower() == "object":
                        o["members"].append({"type": "object", "ref": ct[2]})
                    else:
                        spec = parse_service_tokens(ct[1:])
                        o["members"].append({"type": "service", "spec": spec, "raw": " ".join(ct[1:]),
                                             "text": "|".join(x["text"] for x in spec_to_tuples(spec, []))})
                elif typ == "protocol" and k == "protocol-object":
                    n, num = proto_info(ct[1])
                    o["members"].append({"type": "protocol", "protocol": n, "number": num})
                elif typ == "icmp-type" and k == "icmp-object":
                    ic, _ = parse_icmp(ct, 1)
                    o["members"].append({"type": "icmp", "raw": ic["raw"], "icmp_type": ic["type"]})
                elif typ in ("security", "user"):
                    o["members"].append({"type": "raw", "text": c})
                else:
                    raise ParseError("unrecognised child")
            except (ParseError, IndexError) as e:
                o["unparsed_lines"].append(c)
                self.unparsed_count += 1
                self.warn(cl, "object-group %s '%s': %s: %s" % (typ, name, e, c))
        self.objs[typ][name] = o

    # ---- resolution -------------------------------------------------------- #
    def resolve_net(self, name, ctx, path=()):
        obj = self.objs["network"].get(name)
        if obj is None:
            self.unres("network", name, ctx)
            return [{"type": "unresolved", "text": name, "via": list(path) + [name]}]
        if name in path:
            self.warn(obj["source_line"], "cycle in network group '%s' (path %s)" % (name, " > ".join(path)))
            return []
        self.used.add(("network", name))
        via = list(path) + [name]
        if obj["kind"] == "network_object":
            if obj["value"] is None:
                return []
            d = dict(obj["value"])
            d["text"], d["via"] = net_text(d), via
            return [d]
        out = []
        for m in obj["members"]:
            if m["type"] in ("object", "group"):
                out += self.resolve_net(m["ref"], ctx, tuple(via))
            else:
                d = dict(m)
                d["text"], d["via"] = net_text(d), via
                out.append(d)
        return uniq(out)

    def resolve_svc(self, name, ctx, path=()):
        """Service object / service group / protocol group -> list of service tuples."""
        ns = "service" if name in self.objs["service"] else ("protocol" if name in self.objs["protocol"] else None)
        if ns is None:
            self.unres("service", name, ctx)
            return []
        obj = self.objs[ns][name]
        if name in path:
            self.warn(obj["source_line"], "cycle in service group '%s'" % name)
            return []
        self.used.add((ns, name))
        via = list(path) + [name]
        out = []
        if obj["kind"] == "service_object":
            if obj["value"]:
                out += spec_to_tuples(obj["value"], via)
        elif obj["kind"] == "service_group":
            for m in obj["members"]:
                if m["type"] == "port":
                    protos = ["tcp", "udp"] if obj["ptype"] == "tcp-udp" else [obj["ptype"] or "tcp"]
                    out += [mk_tuple(p, dst=m["text"], via=via) for p in protos]
                elif m["type"] == "service":
                    out += spec_to_tuples(m["spec"], via)
                elif m["type"] in ("object", "group"):
                    out += self.resolve_svc(m["ref"], ctx, tuple(via))
        elif obj["kind"] == "protocol_group":
            for m in obj["members"]:
                if m["type"] == "protocol":
                    out.append(mk_tuple(m["protocol"], via=via))
                elif m["type"] == "group":
                    out += self.resolve_svc(m["ref"], ctx, tuple(via))
        return uniq(out)

    def resolve_leaf_group(self, ns, name, ctx, path=()):
        """Port groups (ns=service) and ICMP-type groups -> list of text strings."""
        obj = self.objs[ns].get(name)
        if obj is None:
            self.unres(ns, name, ctx)
            return []
        if name in path:
            self.warn(obj["source_line"], "cycle in %s group '%s'" % (ns, name))
            return []
        self.used.add((ns, name))
        out = []
        for m in obj["members"]:
            if m["type"] == "port":
                out.append(m["text"])
            elif m["type"] == "icmp":
                out.append(m["raw"])
            elif m["type"] == "group":
                out += self.resolve_leaf_group(ns, m["ref"], ctx, tuple(path) + (name,))
        return list(dict.fromkeys(out))

    def compute_group_views(self):
        saved, self.used = self.used, set()
        for ns, d in self.objs.items():
            for name, o in d.items():
                ctx = "group %s" % name
                if o["kind"] == "network_group":
                    o["members_resolved"] = self.resolve_net(name, ctx)
                elif o["kind"] in ("service_group", "protocol_group"):
                    o["members_resolved"] = self.resolve_svc(name, ctx)
                elif o["kind"] == "icmp_group":
                    o["members_resolved"] = [{"text": x} for x in self.resolve_leaf_group("icmp-type", name, ctx)]
        self.used = saved

    def is_port_group(self, name):
        g = self.objs["service"].get(name)
        return bool(g and g["kind"] == "service_group" and g["ptype"] in ("tcp", "udp", "tcp-udp"))

    # ---- ACL handling ------------------------------------------------------ #
    def acl(self, name, ln):
        if name not in self.acls:
            self.acls[name] = {"name": name, "type": "extended", "bound": False, "rules": [],
                               "remarks": [], "orphan_remarks": [], "_pos": 0, "_count": 0,
                               "_pending": [], "source_line": ln}
        return self.acls[name]

    def handle_acl_line(self, ln, hdr):
        m = REMARK_RE.match(hdr)
        t = hdr.split()
        acl = self.acl(t[1], ln)
        if m:
            text = m.group(3) or ""
            acl["_pos"] = int(m.group(2)) if m.group(2) else acl["_pos"] + 1
            acl["_pending"].append(text)
            acl["remarks"].append({"text": text, "config_position": acl["_pos"], "source_line": ln})
            return
        try:
            rule = self.parse_rule(ln, hdr, t)
        except (ParseError, IndexError, ValueError) as e:
            rule = {"acl": t[1], "rule_type": "unknown", "action": None, "parse_error": str(e),
                    "raw": hdr, "source_line": ln, "inactive": False, "source": None,
                    "destination": None, "service_resolved": []}
            self.unparsed_count += 1
            self.warn(ln, "rule parse error: %s: %s" % (e, hdr[:100]))
        explicit = rule.pop("_explicit", None)
        acl["_pos"] = explicit if explicit else acl["_pos"] + 1
        acl["_count"] += 1
        rule["rule_number"] = acl["_count"]
        rule["config_position"] = acl["_pos"]
        rule["description"] = "\n".join(acl["_pending"])
        rule["description_lines"] = list(acl["_pending"])
        acl["_pending"] = []
        if rule.get("rule_type") not in (None, "unknown"):
            acl["type"] = rule["rule_type"]
        acl["rules"].append(rule)

    def handle_access_group(self, ln, t):
        b = {"acl": t[1], "direction": None, "interface": None, "global": False,
             "per_user_override": False, "source_line": ln}
        if t[2].lower() == "global":
            b["global"], b["direction"] = True, "global"
        else:
            b["direction"] = t[2].lower()
            b["interface"] = t[4] if len(t) > 4 else None
            b["per_user_override"] = any(x.lower() == "per-user-override" for x in t[5:])
        self.bindings.append(b)

    # ---- rule parsing ------------------------------------------------------ #
    def parse_rule(self, ln, hdr, t):
        name, i, explicit = t[1], 2, None
        if t[i].lower() == "line":
            explicit = int(t[i + 1])
            i += 2
        rtype = "extended"
        if t[i].lower() in ("extended", "standard", "webtype", "ethertype"):
            rtype = t[i].lower()
            i += 1
        rule = {"acl": name, "rule_type": rtype, "action": None, "protocol": None, "source": None,
                "source_port": None, "destination": None, "destination_port": None, "service": None,
                "service_resolved": [], "icmp": None, "log": {"enabled": False, "level": None, "interval": None},
                "time_range": None, "inactive": False, "raw": hdr, "source_line": ln,
                "parse_error": None, "unparsed_tokens": [], "_explicit": explicit}
        if rtype in ("webtype", "ethertype"):
            rule["action"] = t[i].lower() if i < len(t) else None
            return rule
        action = t[i].lower()
        if action not in ("permit", "deny"):
            raise ParseError("expected permit/deny, got '%s'" % t[i])
        rule["action"] = action
        i += 1
        ctx = "rule %s#%s (line %d)" % (name, self.acls[name]["_count"] + 1, ln)

        if rtype == "standard":
            rule["source"], i = self.parse_addr(t, i)
            self.annotate_addr(rule["source"], ctx)
            return rule

        # protocol / service
        tok = t[i].lower()
        if tok in ("object", "object-group"):
            ref = t[i + 1]
            rule["protocol"] = {"raw": "%s %s" % (t[i], ref), "kind": "object" if tok == "object" else "group",
                                "ref": ref, "name": None, "number": None}
            rule["service"] = {"raw": rule["protocol"]["raw"], "ref": ref,
                               "inline_generated": bool(DM_RE.match(ref))}
            i += 2
        else:
            n, num = proto_info(t[i])
            rule["protocol"] = {"raw": t[i], "kind": "protocol", "ref": None, "name": n, "number": num}
            i += 1
        pname = rule["protocol"]["name"]
        ports_ok = pname in ("tcp", "udp", "sctp")

        rule["source"], i = self.parse_addr(t, i)
        if ports_ok and i < len(t):
            if t[i].lower() in OPS:
                rule["source_port"], i = parse_port_spec(t, i)
            elif t[i].lower() == "object-group" and i + 2 < len(t) and self.is_port_group(t[i + 1]):
                rule["source_port"] = {"op": "group", "raw": "object-group %s" % t[i + 1], "ref": t[i + 1],
                                       "inline_generated": bool(DM_RE.match(t[i + 1]))}
                i += 2
        rule["destination"], i = self.parse_addr(t, i)
        if ports_ok and i < len(t):
            if t[i].lower() in OPS:
                rule["destination_port"], i = parse_port_spec(t, i)
            elif t[i].lower() == "object-group":
                rule["destination_port"] = {"op": "group", "raw": "object-group %s" % t[i + 1],
                                            "ref": t[i + 1], "inline_generated": bool(DM_RE.match(t[i + 1]))}
                i += 2
        elif pname in ("icmp", "icmp6") and i < len(t) and t[i].lower() not in OPT_KW:
            if t[i].lower() == "object-group":
                rule["icmp"] = {"raw": "object-group %s" % t[i + 1], "group": t[i + 1],
                                "inline_generated": bool(DM_RE.match(t[i + 1]))}
                i += 2
            else:
                rule["icmp"], i = parse_icmp(t, i)

        self.parse_options(t, i, rule, ln)
        self.annotate_addr(rule["source"], ctx)
        self.annotate_addr(rule["destination"], ctx)
        rule["service_resolved"] = self.rule_services(rule, ctx)
        if rule["time_range"]:
            self.used.add(("time-range", rule["time_range"]))
        return rule

    def parse_addr(self, t, i):
        if i >= len(t):
            raise ParseError("missing address")
        tok, l = t[i], t[i].lower()
        if l in ("any", "any4", "any6"):
            return {"raw": tok, "type": l}, i + 1
        if l == "host":
            ip, alias = self.alias_ip(t[i + 1])
            return {"raw": "host %s" % t[i + 1], "type": "host", "value": ip, "alias": alias}, i + 2
        if l in ("object", "object-group"):
            return {"raw": "%s %s" % (tok, t[i + 1]), "type": "object" if l == "object" else "group",
                    "ref": t[i + 1]}, i + 2
        if l == "interface":
            return {"raw": "interface %s" % t[i + 1], "type": "interface", "value": t[i + 1]}, i + 2
        if l in ("user", "user-group", "object-group-user", "object-group-security"):
            return {"raw": "%s %s" % (tok, t[i + 1]), "type": "identity"}, i + 2
        if l == "security-group":
            return {"raw": " ".join(t[i:i + 3]), "type": "identity"}, i + 3
        if is_ipv6_prefix(tok):
            return {"raw": tok, "type": "ipv6", "value": tok}, i + 1
        ip, alias = self.alias_ip(tok)
        if is_ipv4(ip):
            if i + 1 < len(t) and is_netmask(t[i + 1]):
                return {"raw": "%s %s" % (tok, t[i + 1]), "type": "subnet", "value": ip, "mask": t[i + 1],
                        "cidr": to_cidr(ip, t[i + 1]), "alias": alias}, i + 2
            if alias:
                return {"raw": tok, "type": "host", "value": ip, "alias": alias}, i + 1
        raise ParseError("cannot interpret address token '%s'" % tok)

    def annotate_addr(self, a, ctx):
        if a is None:
            return
        if a["type"] in ("object", "group"):
            a["inline_generated"] = bool(DM_RE.match(a["ref"]))
            a["resolved"] = self.resolve_net(a["ref"], ctx)
        else:
            a["resolved"] = [dict(a, text=net_text(a))]

    def parse_options(self, t, i, rule, ln):
        while i < len(t):
            l = t[i].lower()
            if l == "log":
                lg = {"enabled": True, "level": None, "interval": None}
                i += 1
                if i < len(t) and (t[i].lower() in LOG_LEVELS or t[i].lower() in ("disable", "default")):
                    lg["level"] = t[i].lower()
                    if lg["level"] == "disable":
                        lg["enabled"] = False
                    i += 1
                if i + 1 < len(t) and t[i].lower() == "interval" and t[i + 1].isdigit():
                    lg["interval"] = int(t[i + 1])
                    i += 2
                rule["log"] = lg
            elif l == "time-range" and i + 1 < len(t):
                rule["time_range"] = t[i + 1]
                i += 2
            elif l == "inactive":
                rule["inactive"] = True
                i += 1
            else:
                rule["unparsed_tokens"].append(t[i])
                self.unparsed_count += 1
                self.warn(ln, "unrecognised token '%s' in rule" % t[i])
                i += 1

    def rule_services(self, rule, ctx):
        p = rule["protocol"]
        if p["kind"] in ("object", "group"):
            return self.resolve_svc(p["ref"], ctx)
        name = p["name"]

        def port_list(spec):
            if spec is None:
                return [None]
            if spec["op"] == "group":
                return self.resolve_leaf_group("service", spec["ref"], ctx) or [None]
            return [port_text(spec)]

        if name in ("icmp", "icmp6"):
            ic = rule["icmp"]
            if ic and "group" in ic:
                items = self.resolve_leaf_group("icmp-type", ic["group"], ctx) or [None]
            else:
                items = [icmp_text(ic)]
            return uniq([mk_tuple(name, icmp=x) for x in items])
        if name in ("tcp", "udp", "sctp"):
            return uniq([mk_tuple(name, s, d) for s in port_list(rule["source_port"])
                         for d in port_list(rule["destination_port"])])
        return [mk_tuple(name)]


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #
def member_text(m):
    if "ref" in m:
        return "%s:%s" % (m["type"], m["ref"])
    if m["type"] in ("port", "service", "icmp", "raw"):
        return m.get("text") or m.get("raw", "")
    if m["type"] == "protocol":
        return m["protocol"]
    return net_text(m)


def build_expanded(parser, max_expand):
    rows = []
    for acl in parser.acls.values():
        for r in acl["rules"]:
            if r.get("parse_error") or not r.get("source"):
                continue
            srcs = [x["text"] for x in r["source"].get("resolved", [])] or [r["source"]["raw"]]
            dsts = [x["text"] for x in (r["destination"] or {}).get("resolved", [])] or \
                   [(r["destination"] or {}).get("raw", "")]
            svcs = [x["text"] for x in r.get("service_resolved", [])] or [r["protocol"]["raw"] if r.get("protocol") else ""]
            total = len(srcs) * len(dsts) * len(svcs)
            if total > max_expand:
                parser.warn(r["source_line"], "rule %s#%s expands to %d rows; truncated to %d"
                            % (acl["name"], r["rule_number"], total, max_expand))
            for s, d, v in itertools.islice(itertools.product(srcs, dsts, svcs), max_expand):
                rows.append({"acl": acl["name"], "rule_number": r["rule_number"], "action": r["action"],
                             "source": s, "destination": d, "service": v, "log": r["log"]["enabled"],
                             "inactive": r["inactive"], "description": r["description"],
                             "source_line": r["source_line"]})
    return rows


def apply_dm_mode(parser, mode):
    """Returns (objects_list, inline_index). Mutates rules for 'keep' mode."""
    objs = sorted((o for d in parser.objs.values() for o in d.values()), key=lambda o: o["source_line"])
    inline = [o for o in objs if o["inline_generated"]]
    if mode == "resolve":
        return [o for o in objs if not o["inline_generated"]], inline
    if mode == "keep":
        for acl in parser.acls.values():
            for r in acl["rules"]:
                for k in ("source", "destination"):
                    a = r.get(k)
                    if a and a.get("inline_generated"):
                        a.pop("resolved", None)
                if r.get("service") and r["service"].get("inline_generated"):
                    r["service_resolved"] = []
    return objs, []


def clean_object(o):
    return {k: v for k, v in o.items() if k != "ns"}


CSV_NL_SEP = [" | "]     # replacement for line breaks inside CSV fields (set via --csv-nl-sep)
_NL_RE = re.compile(r"\r\n|\r|\n")


def write_csv(path, fields, rows):
    """One physical line per record: embedded line breaks (e.g. multi-line remarks) are
    replaced with CSV_NL_SEP so line-oriented tools and importers don't split rows."""
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
        w.writeheader()
        for r in rows:
            w.writerow({k: (_NL_RE.sub(CSV_NL_SEP[0], v) if isinstance(v, str) else v)
                        for k, v in r.items()})


def write_outputs(parser, outdir, formats, dm_mode, expand, max_expand, source_file):
    os.makedirs(outdir, exist_ok=True)
    expanded = build_expanded(parser, max_expand) if expand else []
    objects, inline_index = apply_dm_mode(parser, dm_mode)
    used_unref = sorted(
        "%s:%s" % (ns, n) for ns, d in parser.objs.items() if ns not in ("security", "user")
        for n in d if (ns, n) not in parser.used)

    acls_out = []
    for acl in parser.acls.values():
        out = {k: v for k, v in acl.items() if not k.startswith("_")}
        out["orphan_remarks"] = list(acl["_pending"])
        out["bindings"] = [b for b in parser.bindings if b["acl"] == acl["name"]]
        acls_out.append(out)

    model = {
        "metadata": {"device": parser.hostname, "version": parser.version, "source_file": source_file,
                     "parsed_at": datetime.now(timezone.utc).isoformat(), "tool_version": TOOL_VERSION,
                     "dm_inline_mode": dm_mode,
                     "note": "unused_objects = not reachable from any ACL rule; references from NAT, VPN, "
                             "class-maps etc. are not considered"},
        "names": [{"alias": a, **v} for a, v in parser.names.items()],
        "objects": [clean_object(o) for o in objects],
        "inline_groups_index": [clean_object(o) for o in inline_index],
        "acls": acls_out, "acl_bindings": parser.bindings,
        "warnings": parser.warnings, "unresolved_refs": parser.unresolved, "unused_objects": used_unref,
    }

    if "json" in formats:
        with open(os.path.join(outdir, "asa_model.json"), "w", encoding="utf-8") as fh:
            json.dump(model, fh, indent=2, default=str)

    if "csv" in formats:
        # objects.csv
        rows = []
        for o in objects:
            if o["kind"] in ("network_object", "service_object"):
                value = net_text(o["value"]) if o["kind"] == "network_object" and o["value"] else \
                    "|".join(x["text"] for x in spec_to_tuples(o["value"], [])) if o["value"] else ""
            else:
                value = ""
            rows.append({"name": o["name"], "kind": o["kind"], "description": o["description"],
                         "inline_generated": o["inline_generated"], "value": value,
                         "member_count": len(o["members"]),
                         "members": ";".join(member_text(m) for m in o["members"]),
                         "members_resolved": ";".join(x["text"] for x in (o["members_resolved"] or [])),
                         "embedded_nat": o["embedded_nat_raw"] or "", "source_line": o["source_line"]})
        write_csv(os.path.join(outdir, "objects.csv"),
                  ["name", "kind", "description", "inline_generated", "value", "member_count", "members",
                   "members_resolved", "embedded_nat", "source_line"], rows)

        # object_members.csv
        rows = []
        for o in objects:
            for m in o["members"]:
                rows.append({"object": o["name"], "level": "direct", "member": member_text(m), "via": ""})
            for x in (o["members_resolved"] or []):
                rows.append({"object": o["name"], "level": "resolved", "member": x["text"],
                             "via": ">".join(x.get("via", []))})
        write_csv(os.path.join(outdir, "object_members.csv"), ["object", "level", "member", "via"], rows)

        # rules.csv
        rows = []
        for acl in parser.acls.values():
            for r in acl["rules"]:
                src, dst = r.get("source") or {}, r.get("destination") or {}
                rows.append({
                    "acl": acl["name"], "rule_number": r["rule_number"], "config_position": r["config_position"],
                    "action": r.get("action"), "rule_type": r.get("rule_type"),
                    "protocol": (r.get("protocol") or {}).get("raw", ""),
                    "source": src.get("raw", ""), "source_inline_generated": src.get("inline_generated", False),
                    "source_resolved": ";".join(x["text"] for x in src.get("resolved", [])),
                    "source_port": (r.get("source_port") or {}).get("raw", ""),
                    "destination": dst.get("raw", ""), "destination_inline_generated": dst.get("inline_generated", False),
                    "destination_resolved": ";".join(x["text"] for x in dst.get("resolved", [])),
                    "destination_port": (r.get("destination_port") or {}).get("raw", ""),
                    "icmp": (r.get("icmp") or {}).get("raw", ""),
                    "service_resolved": ";".join(x["text"] for x in r.get("service_resolved", [])),
                    "log": (r.get("log") or {}).get("enabled", ""),
                    "log_level": (r.get("log") or {}).get("level") or "",
                    "time_range": r.get("time_range") or "", "inactive": r.get("inactive"),
                    "description": r.get("description", ""), "parse_error": r.get("parse_error") or "",
                    "source_line": r["source_line"], "raw": r["raw"]})
        write_csv(os.path.join(outdir, "rules.csv"),
                  ["acl", "rule_number", "config_position", "action", "rule_type", "protocol", "source",
                   "source_inline_generated", "source_resolved", "source_port", "destination",
                   "destination_inline_generated", "destination_resolved", "destination_port", "icmp",
                   "service_resolved", "log", "log_level", "time_range", "inactive", "description",
                   "parse_error", "source_line", "raw"], rows)

        if expand:
            write_csv(os.path.join(outdir, "rules_expanded.csv"),
                      ["acl", "rule_number", "action", "source", "destination", "service", "log", "inactive",
                       "description", "source_line"], expanded)
    return model


def print_summary(parser, model):
    n_rules = sum(len(a["rules"]) for a in parser.acls.values())
    n_obj = sum(len(d) for ns, d in parser.objs.items())
    print("Device        : %s (ASA %s)" % (parser.hostname, parser.version))
    print("Name aliases  : %d" % len(parser.names))
    print("Objects/groups: %d (of which DM_INLINE: %d)" % (
        n_obj, sum(1 for d in parser.objs.values() for o in d.values() if o["inline_generated"])))
    print("ACLs / rules  : %d / %d" % (len(parser.acls), n_rules))
    for a in parser.acls.values():
        print("   %-30s rules=%-4d remarks=%-3d bound=%s" % (a["name"], len(a["rules"]), len(a["remarks"]), a["bound"]))
    print("Bindings      : %d" % len(parser.bindings))
    print("Unresolved    : %d   Warnings: %d   Unused objects: %d" % (
        len(parser.unresolved), len(parser.warnings), len(model["unused_objects"])))


# --------------------------------------------------------------------------- #
# Self-test sample
# --------------------------------------------------------------------------- #
SAMPLE = """\
: Saved
ASA Version 8.5(1)
!
hostname FW01
names
name 10.9.9.9 MgmtHost description Management station
!
object network WEB1
 host 10.1.1.5
 description Web server 1
object network DMZ-NET
 subnet 10.1.1.0 255.255.255.0
object network PARTNER-RANGE
 range 203.0.113.10 203.0.113.20
object network LOOKUP
 fqdn example.com
object network INSIDE-NET
 subnet 192.168.0.0 255.255.0.0
 nat (inside,outside) dynamic interface
object service SVC-HTTPS-ALT
 service tcp source range 1024 65535 destination eq 8443
 description Alt HTTPS
object service SVC-ECHO
 service icmp echo
object-group network WEB-SERVERS
 description DMZ web tier
 network-object object WEB1
 network-object host 10.1.1.6
 network-object 10.2.0.0 255.255.255.0
object-group network ALL-DMZ
 group-object WEB-SERVERS
 network-object object DMZ-NET
object-group network DM_INLINE_NETWORK_1
 network-object object PARTNER-RANGE
 network-object host 198.51.100.7
 group-object WEB-SERVERS
object-group service WEB-PORTS tcp
 description Web ports
 port-object eq www
 port-object eq https
 port-object range 8080 8090
object-group service DM_INLINE_SERVICE_1
 service-object tcp destination eq ssh
 service-object udp destination eq domain
 service-object object SVC-HTTPS-ALT
 service-object icmp echo
object-group service DM_INLINE_TCP_1 tcp
 port-object eq smtp
 port-object eq 587
object-group protocol DM_INLINE_PROTOCOL_1
 protocol-object tcp
 protocol-object udp
object-group icmp-type ICMP-OK
 icmp-object echo
 icmp-object time-exceeded
object-group network LOOPA
 group-object LOOPB
object-group network LOOPB
 group-object LOOPA
time-range BUSINESS-HRS
 periodic weekdays 8:00 to 18:00
!
access-list outside_in remark Allow partners to web servers
access-list outside_in remark Ticket CHG0001234
access-list outside_in extended permit tcp object-group DM_INLINE_NETWORK_1 object-group WEB-SERVERS object-group WEB-PORTS log informational interval 300
access-list outside_in extended permit object-group DM_INLINE_SERVICE_1 any host 10.1.1.5
access-list outside_in extended permit tcp any host MgmtHost eq 22 time-range BUSINESS-HRS
access-list outside_in extended deny ip any any log
access-list outside_in remark orphan trailing remark
access-list dmz_out remark Mail relays
access-list dmz_out extended permit tcp 10.1.1.0 255.255.255.0 any object-group DM_INLINE_TCP_1
access-list dmz_out extended permit icmp any any object-group ICMP-OK
access-list dmz_out extended permit icmp any any echo-reply inactive
access-list dmz_out extended permit tcp any range 1024 65535 interface outside eq https
access-list dmz_out extended permit object-group DM_INLINE_PROTOCOL_1 object NOSUCH any
access-list dmz_out extended permit udp any any gt 1023 weird-token
access-list vpn_acl standard permit 10.0.0.0 255.0.0.0
access-group outside_in in interface outside
access-group dmz_out out interface dmz
"""


def make_run_dir(base):
    """Create <base>/<YYYY-MM-DD_HH-MM-SS> (no characters illegal on Windows, e.g. ':').
    If the folder already exists (two runs in the same second) a _2, _3... suffix is added."""
    stamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    path, n = os.path.join(base, stamp), 1
    while True:
        try:
            os.makedirs(path)
            return path
        except FileExistsError:
            n += 1
            path = os.path.join(base, "%s_%d" % (stamp, n))


# --------------------------------------------------------------------------- #
def main(argv=None):
    ap = argparse.ArgumentParser(description="Parse Cisco ASA 8.5 objects and rulebase")
    ap.add_argument("config", nargs="?", help="path to show running-config output")
    ap.add_argument("-o", "--outdir", default="output",
                    help="base output folder (default 'output'); each run writes to a new "
                         "<outdir>/YYYY-MM-DD_HH-MM-SS subfolder")
    ap.add_argument("--format", default="json,csv", help="comma list of: json,csv")
    ap.add_argument("--dm-inline", choices=("resolve", "keep", "both"), default="resolve")
    ap.add_argument("--expand", action="store_true", help="also write rules_expanded.csv")
    ap.add_argument("--max-expand", type=int, default=100000, help="max expanded rows per rule")
    ap.add_argument("--strict", action="store_true", help="exit 1 on unresolved refs / unparsed lines")
    ap.add_argument("--selftest", action="store_true", help="run on embedded sample config")
    ap.add_argument("--csv-nl-sep", default=" | ",
                    help="string replacing line breaks inside CSV fields, e.g. multi-line remarks "
                         "(default ' | '); JSON output keeps real newlines")
    args = ap.parse_args(argv)
    CSV_NL_SEP[0] = args.csv_nl_sep

    if args.selftest:
        text, src = SAMPLE, "<selftest>"
        args.expand = True
    elif args.config:
        try:
            with open(args.config, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError as e:
            print("Cannot read %s: %s" % (args.config, e), file=sys.stderr)
            return 2
        src = args.config
    else:
        ap.error("config file required (or --selftest)")

    parser = AsaParser()
    parser.parse(text)
    run_dir = make_run_dir(args.outdir)
    model = write_outputs(parser, run_dir, [f.strip() for f in args.format.split(",")],
                          args.dm_inline, args.expand, args.max_expand, src)
    print_summary(parser, model)
    print("Output written to: %s" % os.path.abspath(run_dir))
    if args.strict and (parser.unresolved or parser.unparsed_count or _LEX):
        print("STRICT: unresolved references or unparsed content found; see warnings.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())