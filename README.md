# asa_parse.py

Extracts the **objects** and **rulebase** from a Cisco ASA (software 8.5) running-config into a
standardised, vendor-neutral format (JSON + CSV), preserving rule numbers, descriptions and remarks.
ASDM-generated `DM_INLINE_*` groups are resolved so every rule shows the actual addresses and
services it matches.

- Python 3.8+, **standard library only**, no install step
- Reads one config file, writes a new timestamped folder per run
- Does not connect to any device and does not modify anything

---

## Contents

1. [Quick start](#1-quick-start)
2. [Input](#2-input)
3. [Command-line options](#3-command-line-options)
4. [What is parsed](#4-what-is-parsed)
5. [Output folder layout](#5-output-folder-layout)
6. [JSON output reference](#6-json-output-reference)
7. [CSV output reference](#7-csv-output-reference)
8. [Behaviour notes](#8-behaviour-notes)
9. [Warnings and troubleshooting](#9-warnings-and-troubleshooting)
10. [Verifying the results](#10-verifying-the-results)
11. [Comparing runs](#11-comparing-runs)
12. [Limitations and not-yet-implemented items](#12-limitations-and-not-yet-implemented-items)

---

## 1. Quick start

```bash
# Smoke test using the built-in sample config (no input file needed)
python asa_parse.py --selftest

# Real run
python asa_parse.py running-config.txt

# Real run, with the one-row-per-source/destination/service CSV, failing on any parse problem
python asa_parse.py running-config.txt --expand --strict
```

Each run creates `output/<YYYY-MM-DD_HH-MM-SS>/` in the current working directory and prints its path.
Add `output/` to your `.gitignore`.

On Windows use `python` or `py`; all examples work unchanged in PowerShell or cmd.

---

## 2. Input

| Item | Detail |
|---|---|
| File | Plain-text output of `show running-config` from a single ASA (or a single context) |
| Software | Written for ASA 8.5 syntax (object / object-group model introduced in 8.3) |
| Encoding | UTF-8; undecodable bytes are replaced rather than aborting. CRLF or LF line endings both work |
| Structure | Child lines must keep their leading-space indentation, as on the device |
| Ignored | Blank lines, lines beginning `!` or `:` (e.g. `: Saved`) |

### Getting a clean config file

```
terminal pager 0
show running-config
```

`terminal pager 0` stops `--More--` prompts being captured in the log. Alternatively use
`more system:running-config`, or in ASDM: *File > Show Running Configuration in New Window* and save the text.

If you use a terminal logger, make sure it doesn't wrap long lines (a wrapped `access-list` line will be
parsed as two broken lines).

For **multiple contexts**, capture and parse each context separately.

The script does not need passwords, keys or SNMP strings. You may remove them before sharing the file;
they are not read.

---

## 3. Command-line options

```
python asa_parse.py [config] [-o OUTDIR] [--format json,csv] [--dm-inline MODE]
                    [--expand] [--max-expand N] [--strict] [--csv-nl-sep STR] [--selftest]
```

| Option | Default | Description |
|---|---|---|
| `config` | (required unless `--selftest`) | Path to the running-config text file |
| `-o`, `--outdir` | `output` | **Base** folder. Each run writes to `<outdir>/<timestamp>/` |
| `--format` | `json,csv` | Comma list of formats to write: `json`, `csv` |
| `--dm-inline` | `resolve` | How `DM_INLINE_*` groups appear in the output (see below) |
| `--expand` | off | Also write `rules_expanded.csv` (one row per source x destination x service) |
| `--max-expand` | `100000` | Maximum expanded rows per rule. Larger rules are truncated and a warning is raised |
| `--strict` | off | Exit code 1 if anything is unresolved or could not be parsed |
| `--csv-nl-sep` | `" \| "` | Replacement for line breaks inside CSV fields (e.g. multi-line remarks) |
| `--selftest` | off | Run against the embedded sample config; forces `--expand` |

### `--dm-inline` modes

| Mode | `DM_INLINE_*` in `objects` / `objects.csv` | In `inline_groups_index` | Rule `resolved` lists for those groups |
|---|---|---|---|
| `resolve` (default) | Hidden | Yes | Kept (the group name is still shown in `ref`) |
| `keep` | Shown as normal groups | No | Removed from rules (`resolved` dropped, `service_resolved` emptied); rules reference the group by name only |
| `both` | Shown | No | Kept |

`rules_expanded.csv` is always built from fully resolved data, whichever mode you choose.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Completed (warnings may still exist, check the summary and JSON) |
| 1 | `--strict` was set and there were unresolved references, unparsed lines/tokens, or unknown port/protocol/ICMP names |
| 2 | Config file unreadable, or bad command-line arguments |

Cycles, duplicates and undefined `access-group` ACLs are reported as warnings but do **not** trigger `--strict` on their own.

---

## 4. What is parsed

### Objects

| Config construct | Supported forms |
|---|---|
| `name <ip> <alias> [description ...]` | Alias table; aliases are substituted in `host` statements, group members and ACEs |
| `object network` | `host`, `subnet` (IPv4 mask or IPv6 prefix), `range`, `fqdn [v4\|v6]`, `description`. `nat` lines inside the object are stored raw in `embedded_nat_raw` and not interpreted |
| `object service` | `service tcp\|udp\|tcp-udp\|sctp [source <op>...] [destination <op>...]`, `service icmp\|icmp6 [type [code]]`, `service <ip-protocol>`, `description` |
| `object-group network` | `network-object host\|object\|<ip> <mask>\|<ipv6/prefix>`, `group-object`, `description` |
| `object-group service NAME tcp\|udp\|tcp-udp` | `port-object eq\|range`, `group-object`, `description` |
| `object-group service NAME` (mixed) | `service-object <proto> ...`, `service-object object`, `group-object`, `description` |
| `object-group protocol` | `protocol-object`, `group-object` |
| `object-group icmp-type` | `icmp-object`, `group-object` |
| `object-group security`, `object-group user` | Members stored as raw text only |
| `time-range` | Name and raw child lines |

Port operators `eq`, `neq`, `lt`, `gt`, `range` are supported. Well-known port names (`www`, `https`, `ssh`,
`domain`...), ICMP type names (`echo`, `unreachable`...) and IP protocol names are translated to numbers.
The original text is always kept alongside the number.

### Rulebase

`access-list` lines of the form:

```
access-list <name> [line <n>] [extended] {permit|deny} <protocol> <src> [<src-port>] <dst> [<dst-port>|<icmp>]
            [log [<level>|disable|default] [interval <secs>]] [time-range <name>] [inactive]
```

- `<protocol>`: `ip`, `tcp`, `udp`, `icmp`, `icmp6`, any named/numbered protocol, `object <service-object>`,
  `object-group <protocol-group or service-group>`
- `<src>` / `<dst>`: `any`, `any4`, `any6`, `host <ip>`, `<ip> <mask>`, `<ipv6/prefix>`, `object`, `object-group`,
  `interface <name>`, a `name` alias, and identity forms (`user`, `user-group`, `security-group`... captured as raw text)
- Ports: `eq|neq|lt|gt|range`, or `object-group <port group>`, in either source or destination position
- ICMP: `type [code]` or `object-group <icmp-type group>`
- `access-list <name> remark <text>`
- `access-list <name> standard ...`: source only
- `access-list <name> webtype|ethertype ...`: stored with action and raw line only
- `access-group <acl> in|out interface <if> [per-user-override]` and `access-group <acl> global`

Everything else in the config (interfaces, routing, NAT, VPN/crypto, class-maps, AAA...) is skipped without
affecting parsing of the supported blocks.

---

## 5. Output folder layout

```
output/
  2026-10-01_09-36-16/
    asa_model.json          (--format json)
    objects.csv             (--format csv)
    object_members.csv
    rules.csv
    rules_expanded.csv      (only with --expand)
  2026-10-01_14-02-45/
    ...
```

- Folder names use `YYYY-MM-DD_HH-MM-SS` in **local time**, with no characters that are illegal on Windows.
- If two runs start in the same second, the second folder gets `_2`, then `_3`, and so on. Nothing is overwritten.
- The script prints a summary to the console (device, counts, per-ACL rule/remark counts, number of
  unresolved references, warnings and unused objects) and the full path of the run folder.

---

## 6. JSON output reference

`asa_model.json` top level:

| Key | Contents |
|---|---|
| `metadata` | `device` (hostname), `version` (ASA version), `source_file`, `parsed_at` (UTC ISO timestamp), `tool_version`, `dm_inline_mode`, `note` |
| `names` | `name` aliases: `alias`, `ip`, `description`, `source_line` |
| `objects` | All objects and groups in config order (see below) |
| `inline_groups_index` | The hidden `DM_INLINE_*` groups when `--dm-inline resolve` |
| `acls` | ACLs with their rules (see below) |
| `acl_bindings` | `access-group` statements |
| `warnings` | `{line, message}` |
| `unresolved_refs` | `{kind, name, referenced_from}` for references to objects that don't exist |
| `unused_objects` | `"<type>:<name>"` for objects not reachable from any ACL rule |

All `source_line` values are 1-based line numbers in the input file.

### Object record (`objects[]`)

| Field | Meaning |
|---|---|
| `name` | Object / group name (case preserved) |
| `kind` | `network_object`, `service_object`, `network_group`, `service_group`, `protocol_group`, `icmp_group`, `other_group`, `time_range` |
| `description` | From the `description` line (verbatim) |
| `inline_generated` | `true` for names starting `DM_INLINE_` |
| `ptype` | For service groups: `tcp`, `udp`, `tcp-udp`, or `null` for mixed groups |
| `value` | Simple objects only. Network: `{type: host\|subnet\|ipv6\|range\|fqdn, value, mask, cidr, alias, ...}`. Service: `{protocol, protocol_number, source_port, destination_port, icmp}` |
| `members` | Direct members exactly as configured (`type` = `host`, `subnet`, `ipv6`, `object`, `group`, `port`, `service`, `protocol`, `icmp`, `raw`) |
| `members_resolved` | Groups only: fully flattened, de-duplicated list. Each item has `text` and `via` (the chain of group/object names it came through) |
| `embedded_nat_raw` | Raw `nat` line(s) found inside an `object network` |
| `source_line` | Line where the object starts |
| `unparsed_lines` | Child lines the script could not interpret |

Resolved network leaves look like `{"type":"subnet","value":"10.2.0.0","mask":"255.255.255.0","cidr":"10.2.0.0/24","text":"10.2.0.0/24","via":["ALL-DMZ","WEB-SERVERS"]}`.

Resolved service entries ("tuples") look like:
`{"protocol":"tcp","protocol_number":6,"source_ports":null,"destination_ports":"443","icmp":null,"text":"tcp/443","via":[...]}`

`text` formats: `tcp/443`, `tcp/8080-8090`, `udp/gt 1023`, `tcp/8443 (src 1024-65535)`, `icmp/echo`, `ip`.

### ACL record (`acls[]`)

| Field | Meaning |
|---|---|
| `name`, `type` | ACL name; `extended`, `standard`, `webtype` or `ethertype` |
| `bound` | `true` if an `access-group` references it |
| `bindings` | Matching `access-group` records (`direction` = `in`/`out`/`global`, `interface`, `per_user_override`) |
| `rules` | Ordered list of rule records |
| `remarks` | Every remark individually: `text`, `config_position`, `source_line` |
| `orphan_remarks` | Remarks at the end of the ACL with no rule after them |

### Rule record (`acls[].rules[]`)

| Field | Meaning |
|---|---|
| `rule_number` | 1-based position among rules in the ACL, **remarks not counted** |
| `config_position` | Position counting remark lines too, as the ASA numbers lines for `access-list ... line N` |
| `action` | `permit` / `deny` |
| `protocol` | `{raw, kind: protocol\|object\|group, ref, name, number}` |
| `source`, `destination` | `{raw, type, value, ..., ref, inline_generated, resolved[]}`. `resolved` is the flattened list of addresses (each with `text` and `via`) |
| `source_port`, `destination_port` | `{op, raw, values}` or `{op: "group", ref, inline_generated}` for port groups; `null` if none |
| `icmp` | `{raw, type, code}` or `{group, ...}`; `null` if none |
| `service` | Set only when the protocol slot is an object / object-group: `{raw, ref, inline_generated}` |
| `service_resolved` | **Always populated.** Flattened protocol/port tuples the rule matches |
| `log` | `{enabled, level, interval}` |
| `time_range`, `inactive` | As configured |
| `description` | All remarks preceding the rule, joined with `\n` |
| `description_lines` | The same remarks as a list |
| `raw` | The original config line |
| `source_line` | Line number in the config |
| `parse_error` | `null`, or the reason the rule could not be parsed (the rule is still listed so counts stay correct) |
| `unparsed_tokens` | Trailing tokens that weren't recognised |

---

## 7. CSV output reference

All CSVs are UTF-8 with a header row, `\n` line endings, and **one physical line per record**. Line breaks
inside a value (such as two remarks above a rule) are replaced with `--csv-nl-sep` (default ` | `).
Multi-value cells are joined with `;`.

### `objects.csv`
`name, kind, description, inline_generated, value, member_count, members, members_resolved, embedded_nat, source_line`

- `value`: for simple objects only (e.g. `10.1.1.0/24`, `tcp/8443 (src 1024-65535)`)
- `members`: direct members, e.g. `object:WEB1;10.1.1.6;10.2.0.0/24`. References show as `object:NAME` or `group:NAME`
- `members_resolved`: flattened members

### `object_members.csv`
`object, level, member, via`

One row per member. `level` is `direct` or `resolved`; `via` shows the chain of nested groups for resolved rows.

### `rules.csv`
`acl, rule_number, config_position, action, rule_type, protocol, source, source_inline_generated, source_resolved, source_port, destination, destination_inline_generated, destination_resolved, destination_port, icmp, service_resolved, log, log_level, time_range, inactive, description, parse_error, source_line, raw`

- `source` / `destination` / `protocol` show the config as written (e.g. `object-group DM_INLINE_NETWORK_1`)
- `*_resolved` columns show the flattened contents, `;`-separated
- `description` holds all attached remarks, separated by `--csv-nl-sep`

### `rules_expanded.csv` (with `--expand`)
`acl, rule_number, action, source, destination, service, log, inactive, description, source_line`

One row per source x destination x service combination for each rule. `rule_number` repeats across the rows
of the same rule. Rules with parse errors are omitted. Where a reference couldn't be resolved, the raw text is
used in place of the missing values.

Large rules can produce very many rows. The `--max-expand` limit stops runaway output.

---

## 8. Behaviour notes

### Rule numbering and remarks
- Remarks are separate lines on the ASA. The script attaches **all consecutive remarks immediately before a rule** to
  that rule's `description`.
- `rule_number` counts rules only. `config_position` counts remarks as well. If a rule has an explicit
  `line N`, that number is used for `config_position`.
- If your remarks act as section headings rather than rule descriptions, use `acls[].remarks[]` in the JSON, which lists
  every remark with its position.

### Group resolution
- Nested groups (`group-object`, `network-object object`, `service-object object`) are flattened to any depth.
- Circular references are detected, reported as a warning, and do not loop.
- References to undefined objects are listed in `unresolved_refs`; in resolved lists they appear as `type: unresolved`.
- Duplicates in the flattened lists are removed, first occurrence kept.

### Services
- A rule's `service_resolved` is built from the protocol slot (object / group) or from the inline protocol and port
  specifications, including source and destination port groups.
- `tcp-udp` entries in service objects and groups expand into one `tcp` and one `udp` tuple.
- For a typed port group (`object-group service NAME tcp`) used in a rule, the rule's own protocol is used for the tuples.

### Names (`name` command)
Aliases are substituted for addresses wherever they appear in `host`, group members and ACE address fields. The
alias is kept in the `alias` field.

---

## 9. Warnings and troubleshooting

Warnings are printed in the summary count and listed in the JSON `warnings` array with line numbers.

| Message | Meaning / action |
|---|---|
| `cannot interpret address token 'X'` | An ACE address wasn't recognised (a bare IP without mask/alias, an unusual keyword). Check the line; the rule is kept with `parse_error` set |
| `rule parse error: ...` | The whole ACE failed to parse; see `parse_error` and `raw` in the rule |
| `unrecognised token 'X' in rule` | Extra trailing token after the recognised options. The rule is still parsed; the token is in `unparsed_tokens` |
| `unknown port name 'X'` / `unknown protocol name` / `unknown icmp type` | Name missing from the lookup tables. The original text is kept. Add it to `PORTS`, `PROTOS` or `ICMP_TYPES` near the top of the script |
| `object ... unrecognised child` | A child line inside an object / group wasn't understood; it's stored in `unparsed_lines` |
| `cycle in network group` | Circular group nesting; the loop is broken |
| `duplicate <type> 'X'` | The same name was defined twice; the later definition wins |
| `access-group references undefined ACL` | An `access-group` points at an ACL with no rules in the file |
| `rule X#N expands to ... rows; truncated` | The expanded output hit `--max-expand` |
| Unresolved reference | A rule or group references an object that isn't defined in the file (often a partial or edited config) |

**Rule counts look wrong?** Check the config for wrapped lines or `--More--` artefacts from the capture.

**Everything is skipped / zero objects?** Check indentation survived (some editors strip leading spaces) and that
the file is the running-config, not a `show access-list` or `show object` output.

---

## 10. Verifying the results

The script does not compare itself with the device, so do this on first use:

1. **Rule counts:** the console summary lists rules per ACL. Compare with the count of `access-list <name> ... permit|deny`
   lines in the source: `grep -c "^access-list outside_in .* \(permit\|deny\) " running-config.txt`
   (remarks and `line N` forms need adjusting as appropriate).
2. **Expansion check:** for a handful of rules, including some using DM_INLINE groups, run
   `show access-list <name>` on the ASA, which prints the device's own expansion of each rule, and compare against the
   corresponding rows in `rules_expanded.csv`.
3. **Review `warnings`, `unresolved_refs` and any rule with a non-empty `parse_error`** before relying on the output.
4. Use `--strict` in scripted runs so problems fail loudly.

### Loading the output

```python
import json, csv

model = json.load(open("output/2026-10-01_09-36-16/asa_model.json"))
for acl in model["acls"]:
    for r in acl["rules"]:
        print(acl["name"], r["rule_number"], r["action"], r["description_lines"])

rules = list(csv.DictReader(open("output/2026-10-01_09-36-16/rules.csv", encoding="utf-8")))
```

In Excel, import the CSVs as UTF-8. The `raw` and `description` columns may contain commas, which are quoted correctly.

---

## 11. Comparing runs

Because each run is kept in its own folder, two runs (for example before and after a change window) can be compared directly.

```bash
# Linux / macOS
diff -r output/2026-10-01_09-36-16 output/2026-10-08_09-00-02

# Windows PowerShell (or any platform with git)
git diff --no-index output/2026-10-01_09-36-16 output/2026-10-08_09-00-02
```

- `asa_model.json` always differs on the `parsed_at` line (and `source_file` if the input path changed). Everything else
  is stable for an identical config.
- CSV files are ordered by config position, so a changed, added or removed rule shows up as a localised difference.
- `rule_number` shifts for every rule below an inserted or deleted rule; compare on `raw` or on the
  `source_resolved`/`destination_resolved`/`service_resolved` columns if you only care about content changes.

Suggested `.gitignore` entry:

```
output/
```

---

## 12. Limitations and not-yet-implemented items

- **Not parsed:** NAT (other than the raw `nat` line captured inside `object network`), VPN/crypto, routing, interfaces,
  class-maps/policy-maps, AAA. `access-list` entries used by those features are still read as ACLs, but their
  usage is not tracked.
- **`unused_objects`** only considers references from ACL rules. An object used only in NAT or VPN will be listed as unused.
- **Identity firewall / TrustSec** (`user`, `security-group`, `object-group user|security`) are captured as raw text and not resolved.
- **`standard`** ACLs are parsed for the source address only; **`webtype`/`ethertype`** ACLs keep only the action and the raw line.
- **`any`, `any4`, `any6`** are recorded as written; the script does not interpret whether `any` includes IPv6 on your ASA version.
- **Port-group protocol mismatches** (e.g. a UDP-typed port group used in a `tcp` rule) are not flagged.
- **Single device/context** per run.
- Items in the specification that are **not implemented yet:** automatic reconciliation against `show access-list` output,
  a round-trip (regenerate config) check, a formal JSON schema file, and a unit-test suite. Only the `--selftest` smoke
  test exists. Contributions welcome.
