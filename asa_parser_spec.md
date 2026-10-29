# Cisco ASA (8.5) Objects & Rulebase Extraction: Specification

## 1. Purpose and scope

Parse a Cisco ASA `show running-config` (software 8.5) and emit a standardised, vendor-neutral representation of:

1. **Objects**: network/service objects, object-groups, legacy `name` entries
2. **Rulebase**: extended ACL entries and their interface bindings

All metadata must be preserved: rule number, descriptions, remarks/comments, logging, inactive state, time-range.

**Out of scope:** NAT, VPN/crypto, routing, interfaces (beyond ACL binding), AAA, class-maps/policy-maps. These must be *skipped safely*, not mis-parsed (see 3.6).

## 2. Input

- Plain-text `show running-config` (single context). Multi-context: one file per context.
- Optional supplementary input: `show access-list` output, used only for validation (section 8).
- Encoding UTF-8, tolerate CRLF, trailing whitespace and `: Saved` / `:` banner lines.
- Hierarchy is determined by leading-space indentation; a child line starts with one space, a top-level line with none.

## 3. Parsing requirements

### 3.1 General

- Case-insensitive keywords; preserve original case of object names (ASA names are case-sensitive).
- Record `source_line` (1-based line number in the config) for every parsed item.
- Unrecognised lines inside a supported block are collected in `unparsed_lines`, never silently dropped.
- Descriptions: take everything after `description ` to end of line, verbatim, trimmed. Do not tokenise.

### 3.2 Objects to parse

| Config construct | Children / forms to support |
| --- | --- |
| `name <ip> <alias> [description <text>]` | Legacy name table; aliases may appear in place of IPs anywhere in rules or groups. Build a name->IP map and resolve. |
| `object network <n>` | `host <ip>`, `subnet <ip> <mask>`, `subnet <ipv6/prefix>`, `range <ip1> <ip2>`, `fqdn [v4\|v6] <name>`, `description <text>`. **Also** contains `nat (...)` lines, so capture as raw text on the object (`embedded_nat_raw`), do not interpret. |
| `object service <n>` | `service <proto> [source <op> <port\|range>] [destination <op> <port\|range>]` where proto = tcp/udp/sctp, `service icmp [<type> [<code>]]`, `service icmp6 [...]`, `service <ip-proto-name\|number>`; `description`. |
| `object-group network <n>` | `network-object host <ip>`, `network-object <ip> <mask>`, `network-object <ipv6/prefix>`, `network-object object <n>`, `group-object <n>`, `description`. |
| `object-group service <n> [tcp\|udp\|tcp-udp]` | Legacy protocol-typed form: `port-object eq <port>`, `port-object range <a> <b>`. |
| `object-group service <n>` (no proto) | Mixed form: `service-object <proto> [source <op> <p>] [destination <op> <p>]`, `service-object object <n>`, `service-object icmp [type]`, `group-object <n>`. |
| `object-group protocol <n>` | `protocol-object <tcp\|udp\|icmp\|ip\|number...>`, `group-object`. |
| `object-group icmp-type <n>` | `icmp-object <type>`, `group-object`. |
| `object-group security <n>`, `object-group user <n>` | Capture raw members and description. Do not interpret. Flag as `unsupported_semantics`. |
| `time-range <n>` | Capture name and raw child lines (referenced by ACEs). |

Port operators: `eq`, `neq`, `lt`, `gt`, `range`. Translate well-known names to numbers via a lookup table (www=80, https=443, ssh=22, domain=53, smtp=25, ftp=21, ftp-data=20, telnet=23, pop3=110, imap4=143, ldap=389, ldaps=636, snmp=161, snmptrap=162, ntp=123, sqlnet=1521, etc.), **keeping the original token** in `port_raw`. Same for ICMP type names (echo=8, echo-reply=0, unreachable=3, time-exceeded=11...) and IP protocol names (tcp=6, udp=17, icmp=1, gre=47, esp=50, ah=51, ospf=89, eigrp=88...). Unknown names -> keep raw and raise a warning.

### 3.3 Object-group nesting and resolution

- `group-object` / `network-object object` / `service-object object` may nest to arbitrary depth.
- Provide two views per group: `members` (direct, as configured) and `members_resolved` (fully flattened, de-duplicated, order preserved, each leaf tagged with the path it was reached by).
- Detect and report cycles and references to undefined objects (`unresolved_refs`); never loop or crash.

### 3.4 Rulebase: ACL entries

Parse `access-list <name> ...` lines. Types: **extended** (primary), plus `standard`, `webtype`, `ethertype` captured raw with `rule_type` set accordingly.

Extended ACE grammar to support:

```
access-list <name> [line <n>] [extended] {permit|deny} <protocol> <src> [<src-port>] <dst> [<dst-port>|<icmp-type>]
    [log [<level>|disable|default] [interval <secs>]] [time-range <name>] [inactive]
```

- `<protocol>`: `ip`, `tcp`, `udp`, `icmp`, `icmp6`, name or number, `object <svc-object>`, `object-group <protocol-or-service-group>`.
- `<src>/<dst>`: `any`, `any4`, `any6`, `host <ip>`, `<ip> <mask>`, `<ipv6/prefix>`, `object <n>`, `object-group <n>`, `interface <ifname>`, a `name` alias, `user ...`/`security-group ...` (capture raw).
- Port spec: `eq|neq|lt|gt <port>`, `range <a> <b>`, `object-group <service-group>` (legacy typed groups).
- ICMP spec: type name/number \[code\], or `object-group <icmp-type group>`.
- Trailing options in any order after the destination spec.

### 3.5 Remarks / comments

- `access-list <name> remark <text>` is a separate line preceding the rule(s) it describes.
- **Association rule:** all consecutive remark lines for an ACL immediately preceding an ACE attach to that ACE (joined with `\n`, in order). A remark followed by another remark chain then an ACE attaches all to that ACE.
- Remarks at the end of an ACL with no following ACE -> `orphan_remarks` on the ACL.
- Also store each remark as its own record with `source_line` so the original structure can be rebuilt.
- Explicit `line <n>` in an ACE/remark is honoured as the *configured position* where present (rare in running-config).

### 3.6 Lines to skip safely

Any top-level construct not listed above (nat, route, crypto, interface body, class-map, etc.) is skipped until the next top-level line. `access-list` references inside them are not rules. Their child lines must never be attributed to a preceding object block.

### 3.7 ACL-to-interface binding

Parse `access-group <acl> {in|out} interface <ifname> [per-user-override]` and `access-group <acl> global`. Output as `acl_bindings`. ACLs not bound anywhere are flagged `bound: false`.

## 4. DM_INLINE resolution

ASDM generates groups named `DM_INLINE_NETWORK_<n>`, `DM_INLINE_SERVICE_<n>`, `DM_INLINE_PROTOCOL_<n>`, `DM_INLINE_TCP_<n>`, `DM_INLINE_UDP_<n>`, `DM_INLINE_TCP_UDP_<n>`, `DM_INLINE_ICMP_<n>`. Detect by regex `^DM_INLINE_`.

Requirements:

1. Parse them exactly like any other object-group (3.2).
2. In each rule, store both:
   - the **reference** (`group_ref: "DM_INLINE_NETWORK_12"`, `inline_generated: true`), and
   - the **resolved members** inline in the rule's `source`/`destination`/`service` field.
3. Configurable output mode (`--dm-inline=resolve|keep|both`, default `resolve`). In `resolve` mode the DM_INLINE groups are omitted from the top-level `object_groups` list but retained in an `inline_groups_index` for traceability. In `keep` mode they appear as normal groups.
4. DM_INLINE groups may reference real named objects or groups, so resolve recursively (3.3) and keep the names of the named objects, in addition to their addresses, in the resolved list.
5. A DM_INLINE group used by several rules is expanded in each; the group is not duplicated in the output.

## 5. Output model

Primary output: **JSON**. Secondary: flat **CSV** exports (section 5.4). Both generated from one internal model.

### 5.1 Object record

```json
{
  "name": "WEB-SERVERS",
  "kind": "network_group",            // network_object | service_object | network_group | service_group | protocol_group | icmp_group | name_alias | time_range | other_group
  "description": "DMZ web tier",
  "inline_generated": false,
  "members": [{"type":"object","ref":"WEB1"}, {"type":"host","value":"10.1.1.5"}],
  "members_resolved": [{"type":"host","value":"10.1.1.5","via":["WEB-SERVERS","WEB1"]}],
  "value": null,                      // for simple objects: {"type":"subnet","address":"10.0.0.0","mask":"255.255.255.0","cidr":"10.0.0.0/24"}
  "embedded_nat_raw": null,
  "source_line": 214,
  "unparsed_lines": []
}
```

### 5.2 Rule record

```json
{
  "acl": "outside_access_in",
  "rule_number": 7,                   // 1-based ordinal of ACEs in ACL (remarks excluded)
  "config_position": 9,               // ordinal incl. remark lines, as ASA counts for `line N` insertion
  "action": "permit",
  "protocol": {"raw":"tcp","number":6,"ref":null},
  "source":      {"raw":"object-group DM_INLINE_NETWORK_3", "ref":"DM_INLINE_NETWORK_3", "inline_generated":true, "resolved":[...]},
  "source_port": null,
  "destination": {"raw":"host 192.0.2.10","type":"host","value":"192.0.2.10"},
  "destination_port": {"raw":"eq https","op":"eq","ports":[443]},
  "service": null,                    // set when protocol/ports come from an object/object-group
  "icmp": null,
  "log": {"enabled":true,"level":"informational","interval":300},
  "time_range": null,
  "inactive": false,
  "description": "Allow partners to web VIP",   // attached remark(s)
  "raw": "access-list outside_access_in extended permit tcp ...",
  "source_line": 1021
}
```

`protocol`, `source_port`, `destination_port`, `service` and `icmp` must together be enough to reconstruct the original rule. Where an ACE uses a service object/group, `service.resolved` holds the flattened `{protocol, source_ports, destination_ports}` tuples.

### 5.3 Top-level document

```json
{
  "metadata": {"device":"<hostname>","version":"8.5(1)","source_file":"...","parsed_at":"...","tool_version":"..."},
  "objects": [...], "inline_groups_index": [...],
  "acls": [{"name":"...","type":"extended","bound":true,"rules":[...],"orphan_remarks":[]}],
  "acl_bindings": [...],
  "warnings": [...], "unresolved_refs": [...], "unused_objects": [...]
}
```

`hostname` taken from the `hostname` line; version from `ASA Version` line.

### 5.4 CSV exports

- `objects.csv`: one row per object. Multi-value fields joined by `;`.
- `object_members.csv`: one row per member (direct and resolved, with a `level` column).
- `rules.csv`: one row per rule, with columns for each rule field above; resolved lists joined by `;`.
- `rules_expanded.csv` (optional flag): cartesian expansion, one row per source x destination x service tuple, with `rule_number` repeated. This file is the one most firewall migration and audit workflows want.

## 6. Interfaces

CLI: `asa_parse.py <config.txt> -o <outdir> [--format json,csv] [--dm-inline resolve|keep|both] [--expand] [--strict]`

- `--strict`: exit non-zero if any `unresolved_refs`, `unparsed_lines` in supported blocks, or unknown tokens are found.
- Exit codes: 0 ok, 1 warnings under strict, 2 fatal input error.
- Importable module exposing `parse_config(text) -> Model` for reuse.

## 7. Implementation notes

- Recommended: Python 3.10+, `ciscoconfparse2`/`ciscoconfparse` for the block tree, `ipaddress` for IP/mask/CIDR conversion and validation. Use a hand-written tokeniser for ACE lines. Regex alone will become unmaintainable for the ACE grammar.
- Two-pass design: pass 1 builds all objects/groups/names; pass 2 parses ACEs and resolves references. This handles forward references.
- Wildcard/netmask: ASA uses normal netmasks in ACEs; convert to CIDR, but keep the raw mask.
- Preserve ordering everywhere (rules, members).

## 8. Validation and test requirements

1. **Count reconciliation:** number of parsed ACEs per ACL equals the count of `access-list <name> ... permit|deny` lines in the file.
2. **Expansion check (if `show access-list` supplied):** per ACL, the number of expanded elements reported by the device (`show access-list <name>`) equals the number of tuples produced by `rules_expanded`. Mismatches reported per rule.
3. **Reference integrity:** every `object`/`object-group`/`name` reference resolves, or appears in `unresolved_refs`.
4. **Round-trip sample:** a regenerated ASA-style text from the model must be semantically equal to the input for a sample set.
5. **Unit-test fixtures covering at least:**
   - every object and object-group type and member form in 3.2
   - nested groups 3+ levels deep, a cycle, an undefined reference
   - `name` aliases used in ACEs and groups
   - DM_INLINE groups of each type, including nested named groups
   - ACEs with: `any/any4/any6`, `host`, mask, `interface`, object, object-group; every port operator; ICMP type; `log` variants; `time-range`; `inactive`
   - remarks: single, multiple, trailing, with special characters
   - descriptions containing quotes, commas, `#`, `!` and 200-character text
   - IPv6 objects and ACEs
   - ACLs not bound, bound `in`, `out` and `global`
   - nat lines inside `object network`
   - CRLF file and tab/trailing-space noise
6. **Acceptance:** run on the real config; zero unexplained entries in `unparsed_lines` for supported blocks; all warnings reviewed.

## 9. Known edge cases to handle explicitly

- Same object-group name cannot be both network and service type but the same name *can* appear after a type change in poorly-edited configs, so key the symbol table by (kind, name).
- `object-group service NAME tcp` members have implicit protocol; do not require a protocol token on `port-object`.
- `range` ports in object-groups vs `range` in ACEs (different positional syntax).
- Rules where the "protocol" slot is an `object-group` that turns out to be a service group, so the ports are then absent from the ACE itself.
- `any` in 8.5 means IPv4+IPv6 on some versions; record raw and don't assume.
- Remarks containing the word `permit`/`deny` must not be treated as rules.
- ASA truncates nothing in `show run`, but long descriptions may wrap in copied terminal output. Detect lines starting with unexpected indentation inside an `access-list` and warn.

## 10. Deliverables

1. Parser module + CLI
2. JSON schema file for the output model
3. Test suite and sanitised fixtures
4. README with field dictionary and run instructions
5. Parse report (counts of objects, groups, ACLs, rules, warnings)