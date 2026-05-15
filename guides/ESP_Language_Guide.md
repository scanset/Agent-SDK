# ESP Language Guide

A hands-on tutorial for learning the Endpoint State Policy language.

---


<!-- SECTION: table-of-contents -->
## Table of Contents

1. [Introduction](#part-1-introduction)
2. [ESP Fundamentals](#part-2-esp-fundamentals)
3. [Building Your First Policy](#part-3-building-your-first-policy)
4. [Intermediate Patterns](#part-4-intermediate-patterns)
5. [Advanced Techniques](#part-5-advanced-techniques)
6. [Real-World Examples](#part-6-real-world-examples)
7. [Cookbook: Common Patterns](#cookbook-common-patterns)
8. [Troubleshooting](#part-7-troubleshooting)
9. [Quick Reference](#part-8-quick-reference)
10. [CTN Type Reference](#part-9-ctn-type-reference)
11. [META Block Reference](#part-10-meta-block-reference)
12. [Result Envelope](#part-11-result-envelope)

---


<!-- SECTION: part-1-introduction -->
## Part 1: Introduction


<!-- SECTION: what-is-esp -->
### What is ESP?

ESP (Endpoint State Policy) is a declarative language for expressing security and compliance rules. Unlike traditional compliance tools that mix policy and execution code, ESP treats policies as pure data definitions that can be:

- Validated automatically by compliance scanners
- Versioned and tracked like any other data
- Reused across different platforms and environments
- Audited and reviewed by humans


<!-- SECTION: core-design-principles -->
### Core Design Principles

1. **Policy as Data** — Policies describe *what* should be true, not *how* to check it
2. **Fail-Fast Validation** — Errors caught at compile time, not runtime
3. **Contract-Driven Extensibility** — CTN types defined by contracts
4. **Deterministic Evaluation** — Same policy + same state = same result
5. **Compliance-Ready Output** — Results mappable to standard formats
6. **Trust Boundaries** — Inputs untrusted, outputs controlled


<!-- SECTION: why-learn-esp -->
### Why Learn ESP?

| Benefit | Description |
|---------|-------------|
| Universal | Write once, apply everywhere (Linux, Windows, cloud, containers) |
| Declarative | Define WHAT should be true, not HOW to check it |
| Version Control | Track policy changes over time |
| Auditable | Human-readable policies that can be reviewed and approved |


<!-- SECTION: learning-path -->
### Learning Path

| Part | Time | Topics |
|------|------|--------|
| 1 | 30 min | Introduction |
| 2 | 1 hour | Core concepts: Objects, States, Criteria |
| 3 | 1.5 hours | Building your first complete policy |
| 4 | 2 hours | Variables, multiple checks, logic operators |
| 5 | 2 hours | Sets, filters, runtime operations |
| 6 | 2 hours | Real-world STIG and CIS implementations |
| 7-8 | 1 hour | Troubleshooting and quick reference |


<!-- SECTION: prerequisites -->
### Prerequisites

- Basic understanding of IT security concepts (file permissions, services, packages)
- Familiarity with compliance frameworks (STIG, CIS, NIST) — helpful but not required

---


<!-- SECTION: agent-usage -->
## Agent Usage

The ESP Agent scans policies and produces compliance results in multiple formats.


<!-- SECTION: basic-commands -->
### Basic Commands

```bash
# Scan a single policy file (console output only)
esp_agent policy.esp

# Scan all ESP files in a directory
esp_agent /path/to/policies/

# Save the signed AssessorPackage envelope to a file
esp_agent --output assessor_package.json policy.esp

# Quiet mode (file output only, no console)
esp_agent --quiet --output assessor_package.json /path/to/policies/
```


<!-- SECTION: command-line-options -->
### Command-Line Options

| Option | Description |
|--------|-------------|
| `-h, --help` | Show help message |
| `-q, --quiet` | Suppress console output |
| `-o, --output <file>` | Write the signed AssessorPackage JSON to `<file>` |


<!-- SECTION: output -->
### Output

Every scan produces a single signed `AssessorPackage` envelope containing
all policies the run touched, with the engine-computed `replay_hash` and a
per-deployment signer identity. Results are printed to the console unless
`--quiet` is set; `--output` additionally writes the JSON envelope to a
file for downstream processing.


<!-- SECTION: exit-codes -->
### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All policies passed |
| 1 | One or more policies failed |
| 2 | Execution error |


<!-- SECTION: examples -->
### Examples

```bash
# Console output only
esp_agent policy.esp

# Console + file output
esp_agent --output assessor_package.json policy.esp

# Batch scan, file only, no console
esp_agent --quiet -o assessor_package.json /path/to/policies/
```


<!-- SECTION: logging-levels -->
### Logging Levels

Control verbosity with `ESP_LOGGING_MIN_LEVEL`:

| Level | What You See |
|-------|--------------|
| `debug` | Everything (tokens, symbols, validation steps) |
| `info` | Phase completions, scan results (default) |
| `warning` | Potential issues, non-critical problems |
| `error` | Only critical errors |

```bash
# Linux/Mac
export ESP_LOGGING_MIN_LEVEL=debug
esp_agent policy.esp
```

---


<!-- SECTION: part-2-esp-fundamentals -->
## Part 2: ESP Fundamentals


<!-- SECTION: how-esp-works -->
### How ESP Works

| Step | What Happens |
|------|--------------|
| 1. Write Policy | Define what should be checked |
| 2. Compile | Compiler validates syntax, types, references |
| 3. Collect Data | Scanner gathers actual system state |
| 4. Compare | Scanner compares actual vs expected |
| 5. Report | You get PASS, FAIL, or ERROR for each check |


<!-- SECTION: outcome-types -->
### Outcome Types

Every evaluation produces one of three outcomes:

| Outcome | Description |
|---------|-------------|
| `Pass` | Compliance check succeeded — system is compliant |
| `Fail` | Compliance check found non-compliance |
| `Error` | Compliance check could not complete (system issue) |


<!-- SECTION: policy-categories-asset_internal-vs-asset_list -->
### Policy Categories: `asset_internal` vs `asset_list`

Every ESP policy fits into one of two shapes, depending on where the
"asset under evaluation" lives relative to the policy file. The shape
determines how you write OBJECT blocks.

| Category | The asset is… | OBJECTs describe… | Typical platforms |
|---|---|---|---|
| `asset_internal` | The thing the scanner runs against (a host, a database, a cluster). The asset IS the scan target. | Sub-items *inside* that asset — file paths, kernel parameters, services, configuration keys. | RHEL9, Windows, PostgreSQL, Kubernetes API |
| `asset_list` | Each external resource the policy enumerates. The scanner authenticates to a control plane and the asset is each named resource. | The resources themselves — by name, by ID, by tag. Often grouped under a `SET` for multi-target evaluation. | AWS, Azure, M365, any cloud / SaaS API |

Authors declare which shape a policy uses via the optional `category`
META field:

```esp
META
    esp_id `r9-rhel-09-211010-os-release-001`
    ...
    category `asset_internal`        # host-mode: the RHEL 9 host is the asset
    ...
META_END
```

```esp
META
    esp_id `cmmc-l1-3-14-2-az-defender-plan2-001`
    ...
    category        `asset_list`
    target_asset_type `Microsoft.Security/pricings`   # what the listed assets ARE
    ...
META_END
```

When `category` is `asset_list`, an additional `target_asset_type` field
names the resource taxonomy each OBJECT entry represents — `aws.s3.bucket`,
`Microsoft.Security/pricings`, `m365.user`, etc. Downstream tooling uses
this pair to route policies onto matching inventory rows and to schedule
scans against the right control planes.

**Authoring rule of thumb:** if your scanner needs to log into one place
to check many things, it's `asset_list`. If it logs into the *target itself*
and inspects the target's interior, it's `asset_internal`.

Both fields are optional in the DSL grammar — older policies and
quick-and-dirty checks omit them. Production policies that want to
participate in automated routing, drift tracking, and AI-assisted
authoring should declare both where applicable.


<!-- SECTION: your-first-policy -->
### Your First Policy

Check if `/etc/passwd` has secure permissions:

```esp
META
    esp_id `my-first-policy`
    version `1.0.0`
    dsl_schema_version `1.0.0`
    platform `linux`
    criticality `high`
    control_mapping `CIS:6.1.1`
    title `Passwd File Permissions`
META_END

DEF
    STATE secure_permissions
        permissions string = `0644`
    STATE_END

    OBJECT etc_passwd
        path `/etc/passwd`
    OBJECT_END

    CRI AND
        CTN file_metadata
            TEST all all
            STATE_REF secure_permissions
            OBJECT_REF etc_passwd
        CTN_END
    CRI_END
DEF_END
```


<!-- SECTION: policy-structure -->
### Policy Structure

```ebnf
esp_file       ::= metadata? definition
metadata       ::= "META" <metadata_field>* "META_END"
definition     ::= "DEF" <var_decl>* (<state> | <object> | <set>)* <criteria>+ "DEF_END"
criteria       ::= "CRI" ("AND" | "OR") "true"? (<criteria> | <criterion>)+ "CRI_END"
criterion      ::= "CTN" <ctn_type> <test_spec> (<state_ref> | <object_ref> | <set_ref>)+ "CTN_END"
```

| Block | Purpose |
|-------|---------|
| `META...META_END` | Required metadata for the result envelope |
| `DEF...DEF_END` | Wraps the entire policy definition |
| `STATE...STATE_END` | Defines expected conditions |
| `OBJECT...OBJECT_END` | Identifies what to check |
| `CRI...CRI_END` | Groups criteria with logic (AND, OR) |
| `CTN...CTN_END` | A single compliance test connecting STATE + OBJECT |
| `TEST` | How to evaluate the check |


<!-- SECTION: understanding-objects -->
### Understanding Objects

Objects identify targets on your system. The fields required depend on the CTN type being used.

```ebnf
object       ::= "OBJECT" <ident> <object_field>* "OBJECT_END"
object_field ::= <field_name> (<backtick_string> | <var_ref> | <ident>) <newline>
```

```esp
# File object (for file_metadata, file_content)
OBJECT ssh_config
    path `/etc/ssh/sshd_config`
OBJECT_END

# TCP port object (for linux_tcp_listener)
OBJECT ssh_port
    port `22`
OBJECT_END

# Kubernetes resource (for k8s_resource)
OBJECT apiserver_pod
    kind `Pod`
    namespace `kube-system`
    label_selector `component=kube-apiserver`
OBJECT_END
```

**Important:** Each CTN type has specific object field requirements. See [CTN docs](../contracts/) for complete specifications per CTN type.


<!-- SECTION: understanding-states -->
### Understanding States

States define what should be true about an object. When a STATE contains multiple fields, they combine using **implicit AND** — all fields must pass.

```ebnf
state        ::= "STATE" <ident> (<state_field> | <record_check>)+ "STATE_END"
state_field  ::= <field_name> <data_type> <operation> (<backtick_string> | <var_ref>)
record_check ::= "record" <data_type>? <record_content> "record_end"
```

```esp
STATE secure_file
    permissions string = `0600`
    owner string = `0`
STATE_END

STATE is_listening
    listening boolean = true
STATE_END

STATE required_config
    content string contains `PermitRootLogin no`
STATE_END
```

**Important:** Each CTN type supports specific state fields and operations. See [CTN docs](../contracts/) for what fields are available per CTN type.


<!-- SECTION: operators -->
### Operators

| Operator | Meaning | Example |
|----------|---------|---------|
| `=` | Equals | `owner string = \`root\`` |
| `!=` | Not equals | `status string != \`disabled\`` |
| `>` | Greater than | `size int > 1000` |
| `<` | Less than | `size int < 5000` |
| `>=` | Greater or equal | `version version >= \`2.0\`` |
| `<=` | Less or equal | `count int <= 10` |
| `contains` | String contains | `content string contains \`error\`` |
| `not_contains` | String does not contain | `content string not_contains \`DEBUG\`` |
| `starts` | String starts with | `path string starts \`/etc\`` |
| `ends` | String ends with | `filename string ends \`.conf\`` |
| `not_starts` | Does not start with | `path string not_starts \`/tmp\`` |
| `not_ends` | Does not end with | `filename string not_ends \`.bak\`` |
| `ieq` | Case-insensitive equals | `status string ieq \`RUNNING\`` |
| `ine` | Case-insensitive not equals | `mode string ine \`DEBUG\`` |
| `pattern_match` | Regex pattern | `content string pattern_match \`^[0-9]+$\`` |
| `matches` | Regex (alias for `pattern_match`) | `name string matches \`^app-.*\`` |
| `subset_of` | Value is in the given set (string / numeric) | `shell string subset_of \`/bin/bash,/bin/sh\`` |
| `superset_of` | Value covers the given set | `enabled_features string superset_of \`tls,fips\`` |


<!-- SECTION: operator-by-type-compatibility-grid -->
### Operator-by-Type Compatibility Grid

Not every operator works on every type. The compiler (`semantic_analysis/type_checker.rs`)
rejects incompatible pairings at compile time. Use this grid when writing
STATE fields:

| Type | `=` `!=` | `<` `>` `<=` `>=` | `ieq` `ine` | `contains` `not_contains` | `starts` `ends` (`not_*`) | `pattern_match` `matches` | `subset_of` `superset_of` |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| `string` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `int` | ✓ | ✓ | – | – | – | – | ✓ |
| `float` | ✓ | ✓ | – | – | – | – | ✓ |
| `boolean` | ✓ | – | – | – | – | – | – |
| `binary` | ✓ | – | – | ✓ | – | – | – |
| `version` | ✓ | ✓ | – | – | – | – | – |
| `evr_string` | ✓ | ✓ | – | – | – | – | – |
| `record_data` | ✓ | – | – | – | – | – | – |

**Notes:**
- `int` and `float` are NOT interchangeable — operations must use matching types.
- `version` compares using semver-aware ordering (`2.10.0` > `2.9.0`), not lexicographic.
- `evr_string` compares using RPM EVR semantics (epoch:version-release, with `~` pre-release suffix).
- `pattern_match` / `matches` use Rust regex syntax (`regex` crate).
- `subset_of` / `superset_of` accept a comma-separated literal (e.g. `\`a,b,c\``) and check membership.
- Each CTN type further restricts which operators are valid per field via its `allowed_operations` declaration — check the CTN's `.md` spec for the authoritative per-field list.


<!-- SECTION: type-system -->
### Type System

ESP enforces **strict typing** with no implicit conversions.

| Type | Description | Example |
|------|-------------|---------|
| `string` | UTF-8 text | `/etc/passwd` |
| `int` | 64-bit signed integer | `1024` |
| `float` | 64-bit floating point | `3.14159` |
| `boolean` | True/false | `true` |
| `binary` | Raw byte data (base64 in JSON) | File contents |
| `record_data` | Structured data (JSON object) | Nested fields |
| `version` | Semantic version (`MAJOR.MINOR.PATCH`) | `2.4.1` |
| `evr_string` | RPM package version (`epoch:version-release`) | `2:1.8.0-1.el9` |

**Key constraint:** `int` and `float` are NOT interchangeable. Operations must use matching types. The DSL grammar version (`dsl_schema_version` in META) is `1.0.0`; the engine release tag is independent (v2.2.3 at time of writing).


<!-- SECTION: connecting-objects-and-states-with-ctn -->
### Connecting Objects and States with CTN

The CTN (Criterion) connects objects with states for validation:

```ebnf
criterion       ::= "CTN" <ctn_type> <test_spec> <state_ref>+ (<object_ref> | <set_ref>)+ "CTN_END"
test_spec       ::= "TEST" <existence_check> <item_check> <state_operator>?
existence_check ::= "all" | "any" | "none" | "at_least_one" | "only_one"
item_check      ::= "all" | "at_least_one" | "only_one" | "none_satisfy"
state_operator  ::= "AND" | "OR" | "ONE"
state_ref       ::= "STATE_REF" <state_ident>
object_ref      ::= "OBJECT_REF" <object_ident>
set_ref         ::= "SET_REF" <set_ident>
```

```esp
CTN criterion_type
    TEST existence_check item_check [state_operator]
    STATE_REF state_identifier
    OBJECT_REF object_identifier
CTN_END
```

- `criterion_type` — The CTN type (e.g., `file_metadata`, `file_content`, `linux_tcp_listener`)
- `existence_check` — How many objects must exist
- `item_check` — How many objects must pass state validation
- `state_operator` — How to combine multiple state fields (optional, default: AND)

**TEST options:**

| Part | Options | Meaning |
|------|---------|---------|
| Existence | `all` | All expected objects must exist |
| | `any` | No existence constraint |
| | `none` | No objects should exist |
| | `at_least_one` | One or more must exist |
| | `only_one` | Exactly one must exist |
| Item | `all` | All existing objects must pass |
| | `at_least_one` | At least one must pass |
| | `only_one` | Exactly one must pass |
| | `none_satisfy` | No objects satisfy the state |
| State Operator | `AND` | All state fields must match (default) |
| | `OR` | Any state field can match |
| | `ONE` | Exactly one state field must match |

---


<!-- SECTION: part-3-building-your-first-policy -->
## Part 3: Building Your First Policy


<!-- SECTION: example-file-metadata-validation -->
### Example: File Metadata Validation

This example validates system file permissions:

```esp
META
    esp_id `test-file-metadata-001`
    version `1.0.0`
    dsl_schema_version `1.0.0`
    platform `linux`
    criticality `high`
    control_mapping `CIS:6.1.1,CIS:6.1.2,NIST-800-53:AC-6`
    title `Critical System File Permissions`
    description `Validates that critical system files have correct permissions and ownership`
    author `security-team`
    tags `file-permissions,linux,hardening`
META_END

DEF
    # Variables for reusable values
    VAR root_uid string `0`
    VAR root_gid string `0`
    VAR shadow_gid string `42`

    # Objects - System files to check
    OBJECT passwd_file
        path `/etc/passwd`
    OBJECT_END

    OBJECT group_file
        path `/etc/group`
    OBJECT_END

    OBJECT shadow_file
        path `/etc/shadow`
    OBJECT_END

    # States - Expected conditions
    STATE passwd_permissions
        exists boolean = true
        permissions string = `0644`
        owner string = VAR root_uid
        group string = VAR root_gid
    STATE_END

    STATE group_permissions
        exists boolean = true
        permissions string = `0644`
        owner string = VAR root_uid
        group string = VAR root_gid
    STATE_END

    STATE shadow_permissions
        exists boolean = true
        permissions string = `0640`
        owner string = VAR root_uid
        group string = VAR shadow_gid
    STATE_END

    # Criteria - All checks must pass
    CRI AND
        CTN file_metadata
            TEST all all
            STATE_REF passwd_permissions
            OBJECT_REF passwd_file
        CTN_END

        CTN file_metadata
            TEST all all
            STATE_REF group_permissions
            OBJECT_REF group_file
        CTN_END

        CTN file_metadata
            TEST all all
            STATE_REF shadow_permissions
            OBJECT_REF shadow_file
        CTN_END
    CRI_END
DEF_END
```

**Run this policy:**

```bash
esp_agent esp/ksi_svc_vri_r9_file_permissions.esp
```

**Key points:**

1. **META block** requires `esp_id`, `version`, `dsl_schema_version`, `platform`, `criticality`, `control_mapping`, and `title`
2. **Variables** (`VAR`) let you reuse values like UIDs
3. **Objects** use `path` field for file-based CTN types (see [file_metadata.md](../contracts/file_metadata.md))
4. **States** use fields supported by the CTN type
5. **CRI AND** means all checks must pass

---


<!-- SECTION: part-4-intermediate-patterns -->
## Part 4: Intermediate Patterns


<!-- SECTION: example-file-content-validation -->
### Example: File Content Validation

This example validates file contents using string operations:

```esp
META
    esp_id `test-file-content-001`
    version `1.0.0`
    dsl_schema_version `1.0.0`
    platform `linux`
    criticality `medium`
    control_mapping `CIS:5.4.1,NIST-800-53:AC-2`
    title `System Account Configuration Validation`
    description `Validates critical system file content for security compliance`
    author `security-team`
    tags `file-content,linux,accounts`
META_END

DEF
    OBJECT passwd_file
        path `/etc/passwd`
    OBJECT_END

    OBJECT group_file
        path `/etc/group`
    OBJECT_END

    # Verify root account has UID 0 and valid shell
    STATE root_account_valid
        content string contains `root:x:0:0:`
        content string pattern_match `^root:.*:/bin/bash$`
    STATE_END

    # Verify system accounts use nologin shell
    STATE daemon_nologin
        content string contains `daemon:x:1:1:`
        content string contains `/usr/sbin/nologin`
    STATE_END

    # Verify no accounts have empty password field
    STATE no_empty_passwords
        content string not_contains `::0:`
    STATE_END

    # Verify shadow group exists
    STATE shadow_group_exists
        content string contains `shadow:x:`
    STATE_END

    CRI AND
        CTN file_content
            TEST all all
            STATE_REF root_account_valid
            OBJECT_REF passwd_file
        CTN_END

        CTN file_content
            TEST all all
            STATE_REF daemon_nologin
            OBJECT_REF passwd_file
        CTN_END

        CTN file_content
            TEST all all
            STATE_REF no_empty_passwords
            OBJECT_REF passwd_file
        CTN_END

        CTN file_content
            TEST all all
            STATE_REF shadow_group_exists
            OBJECT_REF group_file
        CTN_END
    CRI_END
DEF_END
```

**Key techniques:**
- Multiple state fields with same name (`content`) using different operations
- `contains` for substring matching
- `pattern_match` for regex validation
- `not_contains` for negative assertions

See [file_content.md](../contracts/file_content.md) for all supported operations.


<!-- SECTION: using-variables -->
### Using Variables

Variables define values once for reuse throughout the policy.

```esp
DEF
    VAR config_dir string `/etc/app`
    VAR required_owner string `0`
    VAR secure_perms string `0640`

    OBJECT app_config
        path VAR config_dir
    OBJECT_END

    STATE secure_config
        owner string = VAR required_owner
        permissions string = VAR secure_perms
    STATE_END
DEF_END
```


<!-- SECTION: logic-operators-and-vs-or -->
### Logic Operators: AND vs OR

| Operator | Logic | Use When |
|----------|-------|----------|
| `AND` | All checks must pass | Strict requirements |
| `OR` | At least one must pass | Alternative options |

**CRI AND Evaluation:**

| Children | Result |
|----------|--------|
| [Pass, Pass, Pass] | Pass |
| [Pass, Fail, Pass] | Fail |
| [Pass, Error, Pass] | Error |
| [Fail, Fail, Fail] | Fail |

**CRI OR Evaluation:**

| Children | Result |
|----------|--------|
| [Fail, Fail, Pass] | Pass |
| [Error, Fail, Pass] | Pass |
| [Fail, Fail, Fail] | Fail |
| [Error, Error, Error] | Error |

**Important:** All children are **always evaluated** — no short-circuiting. This ensures complete reporting.

**AND example** — all must pass:

```esp
CRI AND
    CTN file_metadata
        TEST all all
        STATE_REF secure_permissions
        OBJECT_REF config_file
    CTN_END

    CTN linux_tcp_listener
        TEST at_least_one all
        STATE_REF is_listening
        OBJECT_REF app_port
    CTN_END
CRI_END
```

**OR example** — at least one must pass:

```esp
CRI OR
    CTN linux_tcp_listener
        TEST at_least_one all
        STATE_REF is_listening
        OBJECT_REF port_8080
    CTN_END

    CTN linux_tcp_listener
        TEST at_least_one all
        STATE_REF is_listening
        OBJECT_REF port_8443
    CTN_END
CRI_END
```


<!-- SECTION: nested-logic -->
### Nested Logic

Combine AND and OR for complex requirements:

```esp
CRI OR
    # Option 1: port 8080 available
    CRI AND
        CTN linux_tcp_listener
            TEST at_least_one all
            STATE_REF is_listening
            OBJECT_REF port_8080
        CTN_END
    CRI_END

    # Option 2: port 8443 available
    CRI AND
        CTN linux_tcp_listener
            TEST at_least_one all
            STATE_REF is_listening
            OBJECT_REF port_8443
        CTN_END
    CRI_END
CRI_END
```


<!-- SECTION: negate-flag -->
### Negate Flag

The `negate` flag inverts the entire block result after evaluation:

```esp
CRI AND true    # negate = true
    CTN ...     # evaluates to Pass
CRI_END
# Final result: Fail (negated)
```

**Negation rules:**
- `Pass` → `Fail`
- `Fail` → `Pass`
- `Error` → `Error` (unchanged)

---


<!-- SECTION: part-5-advanced-techniques -->
## Part 5: Advanced Techniques


<!-- SECTION: example-tcp-listener-validation -->
### Example: TCP Listener Validation

This example validates network port states:

```esp
META
    esp_id `test-tcp-listener-001`
    version `1.0.0`
    dsl_schema_version `1.0.0`
    platform `linux`
    criticality `medium`
    control_mapping `CIS:3.4.1,NIST-800-53:CM-7`
    title `Network Service Port Validation`
    description `Validates expected TCP listeners and ensures prohibited ports are not listening`
    author `security-team`
    tags `network,tcp,ports,services`
META_END

DEF
    # Ports to check
    OBJECT port_2024
        port `2024`
    OBJECT_END

    OBJECT telnet_port
        port `23`
    OBJECT_END

    OBJECT ftp_port
        port `21`
    OBJECT_END

    OBJECT rsh_port
        port `514`
    OBJECT_END

    # States
    STATE is_listening
        listening boolean = true
    STATE_END

    STATE not_listening
        listening boolean = false
    STATE_END

    CRI AND
        # Verify expected service is listening
        CTN linux_tcp_listener
            TEST at_least_one all
            STATE_REF is_listening
            OBJECT_REF port_2024
        CTN_END

        # Verify insecure services are NOT listening
        CTN linux_tcp_listener
            TEST at_least_one all
            STATE_REF not_listening
            OBJECT_REF telnet_port
        CTN_END

        CTN linux_tcp_listener
            TEST at_least_one all
            STATE_REF not_listening
            OBJECT_REF ftp_port
        CTN_END

        CTN linux_tcp_listener
            TEST at_least_one all
            STATE_REF not_listening
            OBJECT_REF rsh_port
        CTN_END
    CRI_END
DEF_END
```

**Key techniques:**
- Checking that ports ARE listening (expected services)
- Checking that ports are NOT listening (prohibited services)
- Using `TEST at_least_one all` for port checks

See [linux_tcp_listener.md](../contracts/linux_tcp_listener.md) for the complete tcp_listener specification.


<!-- SECTION: sets -->
### Sets

Group multiple objects together with SET operations.

```ebnf
set            ::= "SET" <set_ident> <set_op> <set_operand>+ <filter_block>? "SET_END"
set_op         ::= "union" | "intersection" | "complement"
set_operand    ::= <object_ref> | <set_reference> | <inline_object> | <inline_set>
set_reference  ::= "SET_REF" <set_ident>
filter_block   ::= "FILTER" ("include" | "exclude")? <state_ref> "FILTER_END"
```

| Operation | Description | Operand Count |
|-----------|-------------|---------------|
| `union` | Combine objects (A + B + C) | 1+ |
| `intersection` | Objects in all sets (A ∩ B) | 2+ |
| `complement` | Remove objects (A - B) | Exactly 2 |

```esp
DEF
    OBJECT ssh_config
        path `/etc/ssh/sshd_config`
    OBJECT_END

    OBJECT sudoers_file
        path `/etc/sudoers`
    OBJECT_END

    OBJECT hosts_file
        path `/etc/hosts`
    OBJECT_END

    SET critical_configs union
        OBJECT_REF ssh_config
        OBJECT_REF sudoers_file
        OBJECT_REF hosts_file
    SET_END

    STATE files_exist
        exists boolean = true
    STATE_END

    CRI AND
        CTN file_metadata
            TEST all all
            STATE_REF files_exist
            OBJECT
                SET_REF critical_configs
            OBJECT_END
        CTN_END
    CRI_END
DEF_END
```


<!-- SECTION: filters -->
### Filters

Narrow down which objects in a set should be checked.

| Filter | Behavior |
|--------|----------|
| `include` | Only check objects matching the filter state |
| `exclude` | Skip objects matching the filter state |

```esp
STATE is_large
    size int > 1000
STATE_END

SET large_log_files union
    OBJECT_REF log_file_1
    OBJECT_REF log_file_2
    OBJECT_REF log_file_3
    FILTER include
        STATE_REF is_large
    FILTER_END
SET_END
```


<!-- SECTION: pattern-matching -->
### Pattern Matching

Use `pattern_match` for regex validation:

```esp
STATE valid_ip_format
    content string pattern_match `^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`
STATE_END
```

Common patterns:

| Use Case | Pattern |
|----------|---------|
| IPv4 address | `^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$` |
| Email | `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$` |
| Date (YYYY-MM-DD) | `^\d{4}-\d{2}-\d{2}$` |


<!-- SECTION: record-checks-advanced -->
### Record Checks (Advanced)

Validate structured data (JSON, configuration files, API responses). Used with CTN types like `json_record` and `k8s_resource`. These require SDK implementation.

```esp
STATE json_config_valid
    record
        field settings.enabled boolean = true
        field settings.timeout int > 30
        field users.*.role string = `admin` at_least_one
        field items.0.name string = `primary`
    record_end
STATE_END
```

**Field path syntax:**

| Syntax | Meaning | Example |
|--------|---------|---------|
| `name` | Simple field | `status` |
| `a.b.c` | Nested field | `settings.security.enabled` |
| `arr.0` | Array index (0-based) | `containers.0.image` |
| `arr.*` | Array wildcard | `containers.*.name` |
| `a.*.b` | Nested wildcard | `spec.containers.*.ports.*.containerPort` |

**Entity checks** (for wildcards/arrays):

| Check | Passes When |
|-------|-------------|
| `all` | All matching elements pass (default) |
| `at_least_one` | At least one element passes |
| `none` | No elements pass |
| `only_one` | Exactly one element passes |

See [json_record.md](../contracts/json_record.md) for record check usage with structured JSON, and [Contract-Library/Kubernetes/k8s_resource](https://github.com/scanset/Contract-Library/tree/main/Kubernetes/k8s_resource) for the same pattern applied to Kubernetes API resources.


<!-- SECTION: behavior-directives -->
### BEHAVIOR Directives

Control scanner behavior without changing what you check:

| Behavior | Purpose |
|----------|---------|
| `recursive_scan` | Scan directory recursively |
| `max_depth N` | Limit recursion depth |
| `include_hidden` | Include dotfiles |
| `follow_symlinks` | Follow symbolic links |
| `timeout N` | Command timeout in seconds |

```esp
OBJECT log_directory
    path `/var/log/app`
    behavior recursive_scan max_depth 3 include_hidden false
OBJECT_END
```


<!-- SECTION: run-operations -->
### RUN Operations

Compute values at runtime:

```ebnf
run_block       ::= "RUN" <target_var> <operation_type> <run_parameter>+ "RUN_END"
operation_type  ::= "CONCAT" | "SPLIT" | "SUBSTRING" | "REGEX_CAPTURE"
                  | "ARITHMETIC" | "COUNT" | "EXTRACT"
run_parameter   ::= <literal_param>  | <variable_param> | <object_param>
                  | <pattern_param>  | <delimiter_param>| <character_param>
                  | <position_param> | <arithmetic_op>
literal_param   ::= "literal" (<backtick_string> | <int_value>)
variable_param  ::= "VAR" <ident>
object_param    ::= "OBJ" <object_ident> <field_name>
```

| Operation | Purpose | Input → Output |
|-----------|---------|----------------|
| `CONCAT` | Join strings | string → string |
| `SPLIT` | Split string into array | string → string[] |
| `SUBSTRING` | Extract portion of string | string → string |
| `REGEX_CAPTURE` | Extract via regex | string → string |
| `ARITHMETIC` | Math operations | int/float → same type |
| `COUNT` | Count collection items | collection → int |
| `EXTRACT` | Get field from object | object → field type |

**CONCAT example:**

```esp
RUN full_path CONCAT
    VAR base_dir
    literal `/`
    VAR filename
RUN_END
```

**ARITHMETIC example:**

```esp
RUN computed_threshold ARITHMETIC
    literal 1024
    + 512
    * 2
RUN_END
```


<!-- SECTION: string-literals -->
### String Literals

ESP uses backticks for string literals:

```esp
VAR path string `/etc/ssh/sshd_config`
```

**Escaping backticks:**

```esp
VAR message string `This has a ``backtick`` inside`
```

**Raw strings** (no escape processing):

```esp
VAR regex string r`^\d{3}-\d{4}$`
```

---


<!-- SECTION: part-6-real-world-examples -->
## Part 6: Real-World Examples


<!-- SECTION: kubernetes-api-server-rbac-validation-advanced -->
### Kubernetes: API Server RBAC Validation (Advanced)

This example requires the `k8s_resource` CTN type from the ESP Agent SDK:

```esp
META
    esp_id `stig-v242382-rbac-auth`
    version `1.0.0`
    dsl_schema_version `1.0.0`
    platform `kubernetes`
    criticality `high`
    control_mapping `DISA-STIG:V-242382,NIST-800-53:AC-6`
    title `Kubernetes API Server must have RBAC authorization enabled`
    author `security-team`
    tags `stig,kubernetes,apiserver,authorization,rbac`
META_END

DEF
    OBJECT apiserver_pod
        kind `Pod`
        namespace `kube-system`
        label_selector `component=kube-apiserver`
    OBJECT_END

    STATE uses_rbac
        record
            field spec.containers.0.command string contains `--authorization-mode=Node,RBAC` at_least_one
        record_end
    STATE_END

    CRI AND
        CTN k8s_resource
            TEST all all
            STATE_REF uses_rbac
            OBJECT_REF apiserver_pod
        CTN_END
    CRI_END
DEF_END
```

See [Contract-Library/Kubernetes/k8s_resource](https://github.com/scanset/Contract-Library/tree/main/Kubernetes/k8s_resource) for the Kubernetes CTN spec. The Agent SDK does not ship `k8s_resource` in its default registry — copy the contract folder from Contract-Library into your agent's `contract_kit/` tree to enable it.


<!-- SECTION: json-configuration-validation-advanced -->
### JSON Configuration Validation (Advanced)

This example requires the `json_record` CTN type from the ESP Agent SDK:

```esp
META
    esp_id `json-config-validation`
    version `1.0.0`
    dsl_schema_version `1.0.0`
    platform `linux`
    criticality `medium`
    control_mapping `CIS:5.1.1`
    title `Application Configuration Validation`
META_END

DEF
    OBJECT app_config
        path `/etc/app/config.json`
    OBJECT_END

    STATE valid_config
        record
            field version string = `2.0`
            field database.host string = `localhost`
            field database.port int > 1024
            field security.enabled boolean = true
            field users.*.role string = `user` all
        record_end
    STATE_END

    CRI AND
        CTN json_record
            TEST all all
            STATE_REF valid_config
            OBJECT_REF app_config
        CTN_END
    CRI_END
DEF_END
```

See [json_record.md](../contracts/json_record.md) for JSON validation.

---


<!-- SECTION: cookbook-common-patterns -->
## Cookbook: Common Patterns

Each pattern is a complete, runnable policy — copy and save as `pattern.esp`,
then run `esp_agent pattern.esp`. The `META` block uses sample IDs; substitute
your own for production use.


<!-- SECTION: pattern-1-all-files-must-have-correct-permissions -->
### Pattern 1: ALL Files Must Have Correct Permissions

```esp
META
    esp_id `pattern-1-sensitive-files-permissions`
    version `1.0.0`
    dsl_schema_version `1.0.0`
    platform `linux`
    criticality `high`
    control_mapping `CIS:6.1.4`
    title `Sensitive files must be 0600`
META_END

DEF
    OBJECT shadow_file
        path `/etc/shadow`
    OBJECT_END

    OBJECT gshadow_file
        path `/etc/gshadow`
    OBJECT_END

    STATE secure_permissions
        permissions string = `0600`
    STATE_END

    SET sensitive_files union
        OBJECT_REF shadow_file
        OBJECT_REF gshadow_file
    SET_END

    CRI AND
        CTN file_metadata
            TEST all all          # ALL objects must exist AND ALL must pass
            STATE_REF secure_permissions
            SET_REF sensitive_files
        CTN_END
    CRI_END
DEF_END
```


<!-- SECTION: pattern-2-verify-service-is-not-running -->
### Pattern 2: Verify Service is NOT Running

```esp
META
    esp_id `pattern-2-telnet-not-listening`
    version `1.0.0`
    dsl_schema_version `1.0.0`
    platform `linux`
    criticality `high`
    control_mapping `CIS:2.2.1`
    title `Telnet must not be listening`
META_END

DEF
    OBJECT telnet_port
        port `23`
    OBJECT_END

    STATE not_listening
        listening boolean = false
    STATE_END

    CRI AND
        CTN linux_tcp_listener
            TEST at_least_one all
            STATE_REF not_listening
            OBJECT_REF telnet_port
        CTN_END
    CRI_END
DEF_END
```


<!-- SECTION: pattern-3-multiple-conditions-with-or-logic -->
### Pattern 3: Multiple Conditions with OR Logic

```esp
META
    esp_id `pattern-3-config-either-setting`
    version `1.0.0`
    dsl_schema_version `1.0.0`
    platform `linux`
    criticality `medium`
    control_mapping `CIS:5.2.10`
    title `Config file enables one of two equivalent settings`
META_END

DEF
    OBJECT config_file
        path `/etc/myapp/app.conf`
    OBJECT_END

    STATE has_setting_a
        content string contains `SettingA=enabled`
    STATE_END

    STATE has_setting_b
        content string contains `SettingB=enabled`
    STATE_END

    CRI AND
        CTN file_content
            TEST all all OR          # States combined with OR
            STATE_REF has_setting_a
            STATE_REF has_setting_b
            OBJECT_REF config_file
        CTN_END
    CRI_END
DEF_END
```


<!-- SECTION: pattern-4-using-variables-for-reusability -->
### Pattern 4: Using Variables for Reusability

```esp
META
    esp_id `pattern-4-password-min-length`
    version `1.0.0`
    dsl_schema_version `1.0.0`
    platform `linux`
    criticality `high`
    control_mapping `CIS:5.4.1`
    title `Password minimum length enforced via pwquality`
META_END

DEF
    VAR min_password_length int 15
    VAR config_dir string `/etc/security`

    OBJECT pwquality
        path VAR config_dir
    OBJECT_END

    STATE password_length
        minlen int >= VAR min_password_length
    STATE_END

    CRI AND
        CTN file_content
            TEST all all
            STATE_REF password_length
            OBJECT_REF pwquality
        CTN_END
    CRI_END
DEF_END
```


<!-- SECTION: quick-reference-test-combinations -->
### Quick Reference: TEST Combinations

| Scenario | TEST Specification |
|----------|-------------------|
| All must exist and pass | `TEST all all` |
| Any can exist, all that exist must pass | `TEST any all` |
| Any can exist, at least one must pass | `TEST any at_least_one` |
| None should exist | `TEST none none_satisfy` |
| Exactly one must exist and pass | `TEST only_one only_one` |
| At least one must exist and pass | `TEST at_least_one at_least_one` |

---


<!-- SECTION: part-7-troubleshooting -->
## Part 7: Troubleshooting


<!-- SECTION: common-syntax-errors -->
### Common Syntax Errors

| Error | Cause | Solution |
|-------|-------|----------|
| Missing END marker | Forgot `DEF_END`, `STATE_END`, etc. | Add matching END |
| Undefined reference | `STATE_REF` points to non-existent state | Check spelling |
| Type mismatch | String operator on integer | Match operator to type |
| Invalid backticks | Unbalanced backticks | Escape with ` `` ` |
| Missing META fields | Required v1.0.0 fields missing | Add all required fields |
| Shadowing | Local symbol has same name as global | Rename local symbol |
| Duplicate symbol | Same identifier used twice in scope | Use unique names |


<!-- SECTION: required-meta-fields-v100 -->
### Required META Fields (v1.0.0)

These fields are **required** and will cause validation errors if missing:

- `esp_id`
- `version`
- `dsl_schema_version`
- `platform`
- `criticality`
- `control_mapping`
- `title`


<!-- SECTION: policy-always-fails -->
### Policy Always Fails

Common causes:
- Using `CRI AND` when one check is impossible
- Wrong operator (`!=` instead of `=`)
- Incorrect TEST specification
- Object field names don't match CTN type requirements
- State field missing from collected data → Fail (not Error)

**Solution:** Check [CTN docs](../contracts/) for the correct field names and types for your CTN type.


<!-- SECTION: policy-always-passes -->
### Policy Always Passes

Common causes:
- Using `CRI OR` when all checks should be required
- Using `TEST any` when `TEST all` is needed
- State condition is too permissive


<!-- SECTION: scoping-errors -->
### Scoping Errors

**Duplicate Detection:** Identifiers must be unique within scope. Global symbols share a unified namespace.

```esp
# Error: 'config' already declared
VAR config string `/etc/app.conf`
STATE config    # Duplicate identifier!
    ...
STATE_END
```

**Shadowing Prevention:** Local symbols must not shadow global symbols.

```esp
STATE secure_settings    # Global
    ...
STATE_END

CTN file_content
    STATE secure_settings    # Error: shadows global!
        ...
    STATE_END
CTN_END
```


<!-- SECTION: debugging-tips -->
### Debugging Tips

1. **Start simple** — test each CTN individually
2. **Use debug logging** — `ESP_LOGGING_MIN_LEVEL=debug`
3. **Check references** — verify all `STATE_REF` and `OBJECT_REF` exist
4. **Validate types** — match operators to field types
5. **Read CTN docs** — see [CTN docs](../contracts/) for field requirements

---


<!-- SECTION: part-8-quick-reference -->
## Part 8: Quick Reference


<!-- SECTION: syntax-cheat-sheet -->
### Syntax Cheat Sheet

| Block | Syntax |
|-------|--------|
| Metadata | `META ... META_END` |
| Definition | `DEF ... DEF_END` |
| Variable | `VAR name type value` |
| Object | `OBJECT name ... OBJECT_END` |
| State | `STATE name ... STATE_END` |
| Criteria | `CRI AND/OR ... CRI_END` |
| Criterion | `CTN type ... CTN_END` |
| Set | `SET name union/intersection/complement ... SET_END` |
| Filter | `FILTER include/exclude ... FILTER_END` |
| Run | `RUN name operation ... RUN_END` |
| Record | `record ... record_end` |


<!-- SECTION: common-patterns -->
### Common Patterns

**File permission check:**

```esp
STATE secure_perms
    permissions string = `0600`
STATE_END

OBJECT file
    path `/etc/shadow`
OBJECT_END
```

**TCP port check:**

```esp
STATE is_listening
    listening boolean = true
STATE_END

OBJECT port
    port `22`
OBJECT_END
```

**File content check:**

```esp
STATE required_setting
    content string contains `PermitRootLogin no`
STATE_END

OBJECT config
    path `/etc/ssh/sshd_config`
OBJECT_END
```

---


<!-- SECTION: part-9-ctn-type-reference -->
## Part 9: CTN Type Reference


<!-- SECTION: ctn-types-bundled-with-the-agent-sdk -->
### CTN Types Bundled with the Agent SDK

The Agent SDK ships these CTNs in its default registry, all targeting the
local RHEL 9 / Rocky Linux 9 host. Specs live in [`contracts/`](../contracts/):

| Type | Purpose | Spec |
|------|---------|------|
| `file_metadata` | Permissions, owner, group, size, existence | [file_metadata.md](../contracts/file_metadata.md) |
| `file_content` | Content validation (contains, starts_with, pattern_match, …) | [file_content.md](../contracts/file_content.md) |
| `json_record` | Structured JSON field validation via record checks | [json_record.md](../contracts/json_record.md) |
| `linux_tcp_listener` | TCP port listening state via `/proc/net/tcp` | [linux_tcp_listener.md](../contracts/linux_tcp_listener.md) |
| `os_release` | OS identity + version from `/etc/os-release` | [os_release.md](../contracts/os_release.md) |
| `rpm_package` | Package install state + version | [rpm_package.md](../contracts/rpm_package.md) |
| `systemd_service` | Service active/enabled state via `systemctl show` | [systemd.md](../contracts/systemd.md) |
| `sysctl_parameter` | Kernel parameter via `sysctl -n` | [sysctl.md](../contracts/sysctl.md) |
| `fips_mode` | FIPS 140 status via `fips-mode-setup` + `/proc/sys/crypto/fips_enabled` | [fips_mode.md](../contracts/fips_mode.md) |
| `crypto_policy` | System-wide crypto policy via `update-crypto-policies` | [crypto_policy.md](../contracts/crypto_policy.md) |
| `grub_config` | Bootloader configuration parsing | [grub_config.md](../contracts/grub_config.md) |
| `computed_values` | Derived values for cross-CTN assertions (RUN operations) | see [Contract-Library/RHEL9/computed_values](https://github.com/scanset/Contract-Library/tree/main/RHEL9/computed_values) |


<!-- SECTION: more-ctns-cloud-kubernetes-m365-windows -->
### More CTNs (Cloud, Kubernetes, M365, Windows, …)

The Agent SDK keeps a tight local-host scope. For cloud, container, and
identity-platform CTNs — AWS (44+), Azure (35+), M365 (27), Kubernetes,
PostgreSQL, network probes (TLS / HTTP), and Windows — see the companion
[Contract-Library](https://github.com/scanset/Contract-Library) gallery.
Each contract there ships as a drop-in `contract / collector / executor /
command` quartet plus a `.md` spec — copy the folder into your agent's
`contract_kit/` tree and register the strategy. Windows contracts require
running the scanner on a Windows host (or supplying a Windows-capable
execution context when you build the registry).

**Important:** Before writing a policy, read the CTN type documentation to understand:
- Required object fields
- Available state fields and operations
- Collection behavior and performance characteristics


<!-- SECTION: example-policies -->
### Example Policies

The `esp/` directory ships a set of CMMC / FedRAMP KSI policies for
Rocky 9 — real production-grade examples, not toy snippets. A few highlights:

| File | Demonstrates |
|------|--------------|
| `esp/ksi_svc_vri_r9_file_permissions.esp` | `file_metadata` permissions + ownership checks across critical system files |
| `esp/ksi_cna_ibp_iam_mfa_r9_ssh_hardening.esp` | `file_content` searches in `/etc/ssh/sshd_config` + multiple CRI logic |
| `esp/ksi_afr_ucm_r9_fips_crypto.esp` | `fips_mode` + `crypto_policy` + `file_content` combined |
| `esp/ksi_cmt_rmv_r9_os_release.esp` | `os_release` baseline validation |
| `esp/ksi_iam_mfa_elp_r9_pam_password.esp` | `file_content` PAM configuration enforcement |

See `esp/` for the full set of 17 example policies.


<!-- SECTION: running-examples -->
### Running Examples

```bash
# Run a single policy
esp_agent esp/ksi_svc_vri_r9_file_permissions.esp

# Save the signed AssessorPackage envelope
esp_agent --output result.json esp/ksi_afr_ucm_r9_fips_crypto.esp

# Batch scan every example policy
esp_agent esp/
```

---


<!-- SECTION: part-10-meta-block-reference -->
## Part 10: META Block Reference

The META block provides metadata about your policy. All v1.0.0 required fields **must** be present for valid policies.


<!-- SECTION: required-fields-v100 -->
### Required Fields (v1.0.0)

| Field | Description | Example |
|-------|-------------|---------|
| `esp_id` | Unique policy identifier | `stig-sv253284-sehop-enabled` |
| `version` | Policy revision (content version) | `1.0.0` |
| `dsl_schema_version` | ESP language version | `1.0.0` |
| `platform` | Target platform | `linux`, `windows`, `kubernetes` |
| `criticality` | Severity level | `critical`, `high`, `medium`, `low`, `info` |
| `control_mapping` | Framework:Control mapping | `NIST-800-53:AC-6,CIS:5.1.1` |
| `title` | Human-readable title | `SSH Root Login Disabled` |


<!-- SECTION: recommended-fields -->
### Recommended Fields

| Field | Description | Example |
|-------|-------------|---------|
| `description` | Human-readable description | Any text |
| `author` | Author/team name | `security-team` |
| `agent_type` | Target agent type | `endpoint` |
| `tags` | Comma-separated tags | `ssh,hardening,linux` |
| `category` | Policy shape — `asset_internal` (the scan target IS the asset; OBJECTs are sub-items) or `asset_list` (each OBJECT is its own asset, often a cloud resource) | `asset_internal`, `asset_list` |
| `target_asset_type` | When `category` is `asset_list`, the resource taxonomy each OBJECT belongs to | `aws.s3.bucket`, `Microsoft.Security/pricings`, `m365.user` |

See [Part 2: Policy Categories](#policy-categories-asset_internal-vs-asset_list)
for the distinction between the two shapes.


<!-- SECTION: policy-identity -->
### Policy Identity

Every policy has a canonical identity tuple:

```
(esp_id, version, dsl_schema_version)
```

This tuple uniquely identifies a specific policy revision at a specific DSL version.


<!-- SECTION: control-mapping-format -->
### Control Mapping Format

Format: `FRAMEWORK:CONTROL_ID` pairs separated by commas.

```esp
META
    control_mapping `NIST-800-53:AC-6,CIS:5.1.1,DISA-STIG:V-242382`
META_END
```


<!-- SECTION: criticality-levels-and-default-weights -->
### Criticality Levels and Default Weights

| Criticality | Default Weight | Meaning |
|-------------|---------------|---------|
| `critical` | 1.0 | System compromise or data breach risk |
| `high` | 0.8 | Significant security impact |
| `medium` | 0.5 | Moderate security concern |
| `low` | 0.3 | Minor security improvement |
| `info` | 0.1 | Informational, best practice |


<!-- SECTION: complete-example -->
### Complete Example

```esp
META
    esp_id `rhel9-stig-password-complexity`
    version `1.0.0`
    dsl_schema_version `1.0.0`
    platform `linux`
    criticality `medium`
    control_mapping `DISA-STIG:RHEL-09-611015,NIST-800-53:IA-5`
    title `RHEL 9 Password Complexity Requirements`
    description `Ensures password complexity meets STIG requirements`
    author `security-team`
    tags `stig,password,authentication,rhel9`
META_END
```

---


<!-- SECTION: part-11-result-envelope -->
## Part 11: Result Envelope

When the agent runs a policy it emits a single signed `AssessorPackage`
envelope — the same shape whether you scan one policy or a thousand. This
section documents the JSON output so you can build downstream consumers
without guessing the schema.

The envelope is defined in the engine at `common/src/results/envelope.rs`
and `common/src/results/assessor.rs`. `SCHEMA_VERSION = "2.1.1"` at engine
v2.2.3.


<!-- SECTION: assessorpackage-shape -->
### AssessorPackage Shape

The top-level JSON object has four fields:

```json
{
  "envelope":     { ... },   // signed result envelope (see below)
  "summary":      { ... },   // pass/fail counts + execution metadata
  "policies":     [ ... ],   // per-policy outcome + evidence + findings
  "package_info": { ... }    // package metadata (purpose, format_version, notes)
}
```

`envelope` is the cryptographically-bound root. `policies` carries the
per-policy detail (one entry per `.esp` file that ran).


<!-- SECTION: resultenvelope-fields -->
### ResultEnvelope Fields

```json
{
  "result_id":            "esp-result-1a2b3c4d5e",
  "schema_version":       "2.1.1",
  "agent": {
    "id":           "esp-agent-host-7f3a",
    "name":         "esp-agent",
    "version":      "0.1.0",
    "agent_type":   "cli"
  },
  "host": {
    "host_type":    "linux.host",
    "host_id":      "host-2c4f6a8b",
    "hostname":     "scanner-01",
    "os":           "linux",
    "arch":         "x86_64",
    "attrs":        { },
    "fqdn":         "scanner-01.example.internal"
  },
  "started_at":           "2026-05-14T10:23:45.123Z",
  "completed_at":         "2026-05-14T10:23:47.891Z",
  "replay_hash":          "sha256:9f2b8c1e4d3a...",
  "replay_hash_version":  2,
  "signature":            { ... },
  "identity_status": {
    "bootstrapped": false,
    "signer_id":    "unsigned:agent:scanner-01-sdk",
    "error":        null,
    "error_code":   "BOOTSTRAP_DISABLED"
  },
  "observations":         [ ]
}
```

Field reference:

| Field | Type | Meaning |
|---|---|---|
| `result_id` | string | Per-run identifier, `esp-result-<hex>` |
| `schema_version` | string | Wire schema version (`"2.1.1"` at v2.2.3) |
| `agent` | object | Scanner identity (id, name, version, type) |
| `host` | object | Polymorphic — see HostInfo polymorphism below |
| `started_at` / `completed_at` | ISO-8601 string | Scan window |
| `replay_hash` | string | `sha256:<64-hex>` — canonical hash (see replay_hash semantics below) |
| `replay_hash_version` | int | `1` (legacy) or `2` (engine v2.2.0+, per-CTN-per-OBJECT hash) |
| `signature` | object \| null | Detached signature over `SHA256(replay_hash)` |
| `identity_status` | object | Whether/how the signer is identified |
| `observations` | array | Scanner-emitted notes — API-only, empty for DSL-only runs |


<!-- SECTION: assessorpolicyresult-fields -->
### Per-Policy Results

Each entry in the top-level `policies` array describes one `.esp` file
that was evaluated:

```json
{
  "identity": {
    "esp_id":              "stig-rhel-09-255025-sshd-permit-root",
    "version":             "1.0.0",
    "dsl_schema_version":  "1.0.0",
    "platform":            "linux",
    "criticality":         "high",
    "control_mappings":    ["DISA-STIG:RHEL-09-255025", "NIST-800-53:AC-6"],
    "title":               "SSH must disable root login"
  },
  "outcome":          "Pass",
  "weight":           0.7,
  "findings":         [ ... ],
  "evidence":         { ... },
  "reproducibility":  { ... },
  "observation_refs": [ ]
}
```

- **`outcome`** is `"Pass"`, `"Fail"`, or `"Error"`.
- **`findings`** lists each STATE field that failed, with expected vs.
  actual values. Empty on `Pass`.
- **`evidence`** carries the collected data the executor compared against —
  field-by-field per OBJECT.
- **`reproducibility`** documents the commands the collector ran (binary
  paths, arguments, timeouts) so an auditor can re-execute and verify.
- **`observation_refs`** is a UUID list pointing into the envelope's
  `observations` array — empty unless the agent emitted observations
  programmatically.


<!-- SECTION: hostinfo-polymorphism -->
### HostInfo Polymorphism

`host` is polymorphic on `host_type`. Cloud / SaaS scans set additional
provider-specific fields under `attrs`:

```json
// Linux host
{ "host_type": "linux.host", "host_id": "host-2c4f6a8b",
  "hostname": "vm-01", "os": "linux", "arch": "x86_64", "attrs": {} }

// AWS account
{ "host_type": "aws.account", "host_id": "486027077516",
  "attrs": { "region": "us-east-1", "account_alias": "production" } }

// Azure VM
{ "host_type": "azure.vm", "host_id": "vm-rg-eastus-prod-001",
  "hostname": "vm-rg-eastus-prod-001",
  "attrs": { "subscription_id": "...", "resource_group": "rg-prod" } }

// Microsoft 365 tenant
{ "host_type": "m365.tenant", "host_id": "tenant-00000000-...",
  "attrs": { "domain": "contoso.onmicrosoft.com" } }
```

`host_id` is stable within `host_type` — repeat scans against the same
target produce the same `host_id`.


<!-- SECTION: replay_hash-semantics -->
### `replay_hash` Semantics

`replay_hash` is a SHA-256 hash, prefixed `sha256:`, over a canonical
representation of three layers:

| Layer | Contents | Why |
|---|---|---|
| **Intent** | CTN type, TEST spec, STATE definitions with expected values, OBJECT field declarations | What the policy *meant* |
| **Contract** | Collector ID, collection mode, field mappings | How the engine *resolved* it |
| **Outcome** | Per-OBJECT pass/fail flags, per-field validation results | What *happened* |

Deliberately **excluded** from the hash:

- Host fields (hostname, IPs, OS version)
- Timestamps (`started_at`, `completed_at`, `collected_at`)
- Raw evidence values (file contents, command output)
- Observation UUIDs and bodies

The hash is computed **once** in `ExecutionEngine::execute()` and flows
through every downstream artifact unchanged. Output builders do not
recompute it.

**Use cases:**

- **Drift detection** — same policy + same compliance posture against the
  same target yields the same `replay_hash`, regardless of when you ran
  it or what the file contents happened to be.
- **Attestation deduplication** — two runs with identical outcomes
  collapse into one record in a downstream attestation store.
- **Replay verification** — a reviewer can re-run the policy and compare
  hashes to detect tampering with the collector or executor.

**Per-object hashing.** At engine v2.2.0+, the envelope also carries a
`replay_hash_version` field (`1` legacy, `2` per-CTN-per-OBJECT). Version
2 hashes each `(CTN type, OBJECT)` pair independently so that a single
policy template applied to 100 hosts produces 100 distinguishable hashes
while still deduplicating across identical posture states.


<!-- SECTION: signing-and-identity_status -->
### Signing and `identity_status`

Every envelope ships with an `identity_status` block describing whether
the signer is cryptographically identifiable, and optionally a `signature`
block carrying the actual signature.

**`identity_status` fields:**

```json
{
  "bootstrapped":  false,
  "signer_id":     "software:sha256:8a3f...",
  "error":         null,
  "error_code":    "BOOTSTRAP_DISABLED"
}
```

| `bootstrapped` | `signer_id` prefix | Meaning |
|---|---|---|
| `true` | PKI SAN URI (e.g. `scanset://prod/...`) | Signer obtained a PKI identity from a trust system — fully verifiable |
| `false` | `software:sha256:<fp>` | Ephemeral software key — signature is cryptographically sound but the signer is anonymous |
| `false` | `tpm:sha256:<fp>` | TPM-bound key (Windows backend) |
| `false` | `unsigned:agent:<host>-<suffix>` | No signing at all — `signature` block will be `null` |

`error_code` values:
- `BOOTSTRAP_DISABLED` — explicit configuration, not a failure
- `BOOTSTRAP_CONNECTION_FAILED`, `BOOTSTRAP_AUTH_FAILED`,
  `BOOTSTRAP_CERT_FAILED`, `BOOTSTRAP_TIMEOUT`, `BOOTSTRAP_TLS_ERROR`,
  `BOOTSTRAP_KEY_ERROR` — actual failures bootstrapping a PKI identity

**`signature` block** (when present):

```json
{
  "covers":              ["replay_hash"],
  "algorithm":           "ECDSA-P256",
  "public_key":          "<base64-DER>",
  "signature":           "<base64-DER>",
  "payload":             "<base64-SHA256-of-replay_hash>",
  "certificate_chain":   "<PEM>",         // PKI mode only
  "transparency":        { ... }          // optional CT proof
}
```

The signature covers `SHA256(replay_hash)` — not the whole envelope. The
hash collapses the entire intent-contract-outcome surface into 32 bytes,
which the signer then signs with ECDSA P-256.

**Offline verification** (any consumer with the envelope JSON):

1. Decode `signature.public_key` and `signature.signature` from base64.
2. Compute `SHA256(envelope.replay_hash)` (or use `signature.payload`).
3. Verify the ECDSA-P256 signature against the public key.

For PKI-mode envelopes, also verify `certificate_chain` against a trusted
root CA, and optionally the `transparency` block against the trust
system's append-only Merkle log.


<!-- SECTION: observations -->
### Observations

The `observations` array on the envelope is for scanner-emitted notes
that aren't policy outcomes — bulk evidence collection, asset enumeration,
drift markers. Each observation has a UUID, a content hash, a method
descriptor, and an optional body.

**Observations have NO DSL surface in v2.2.3.** You cannot emit one from
a `.esp` policy. They are populated programmatically by agent code
calling `ResultEnvelope::record_observation()`. This is an extension
point for advanced integrations (e.g., an agent that performs asset
discovery alongside policy evaluation) — most policy-author workflows
leave the array empty.

If you're writing agent code that needs observations, see
`common/src/results/observation.rs` for the API.


---


<!-- SECTION: next-steps -->
## Next Steps

You now have the knowledge to:

- Write basic and advanced ESP policies
- Use variables, logic operators, and sets
- Implement compliance checks using various CTN types
- Read the signed `AssessorPackage` envelope and verify a result offline
- Debug and troubleshoot policy issues

**Resources:**

- [CTN Type Documentation](../contracts/) — Complete field specifications for each CTN type
- [ESP Overview](https://github.com/scanset/Endpoint-State-Policy) — Language overview specification
- [Example Policies](../esp/) — Working policy examples
