# Azure NSG Automation (`nsg-tool`)

A command-line tool for managing **Azure Network Security Group (NSG) rules** safely and repeatably,
instead of clicking through the Azure Portal.

It validates every rule before it reaches Azure. It also detects duplicate, conflicting and shadowed
rules, warns loudly about risky exposure, shows a dry-run or Terraform-style plan before any change,
and writes an audit log of who changed what.

---

## Contents

1. [Project overview](#1-project-overview)
2. [Architecture](#2-architecture)
3. [Prerequisites](#3-prerequisites)
4. [Azure permissions (RBAC)](#4-azure-permissions-rbac)
5. [Installation](#5-installation)
6. [Azure authentication](#6-azure-authentication)
7. [Configuration](#7-configuration)
8. [CLI commands](#8-cli-commands)
9. [JSON configuration](#9-json-configuration)
10. [Dry-run example](#10-dry-run-example)
11. [Plan / apply example](#11-plan--apply-example)
12. [Testing](#12-testing)
13. [Troubleshooting](#13-troubleshooting)
14. [Security considerations](#14-security-considerations)
15. [Example use cases](#15-example-use-cases)
16. [Running from VS Code](#16-running-from-vs-code)

---

## 1. Project overview

| Capability | Command |
|---|---|
| Create an NSG | `nsg-tool create-nsg` |
| Add inbound / outbound rule | `nsg-tool add --direction inbound\|outbound` |
| Update a rule (only the fields you pass) | `nsg-tool update` |
| Delete a rule (with confirmation) | `nsg-tool delete` |
| List rules (optionally with Azure default rules) | `nsg-tool list` |
| Search / filter (by port, IP, name glob, access ...) | `nsg-tool search` |
| Validate a JSON file offline | `nsg-tool validate file.json` |
| Show differences between JSON and Azure | `nsg-tool plan file.json` |
| Make Azure match the JSON exactly | `nsg-tool apply file.json` |
| Export rules to JSON | `nsg-tool export` |
| Import rules from JSON (create/update only, never delete) | `nsg-tool import file.json` |
| Dry run on every write | `--dry-run` |
| Guided prompts | `nsg-tool interactive` |
| Test authentication | `nsg-tool whoami` |

**Why Python?** Microsoft's Python management SDK (`azure-mgmt-network`) and `azure-identity` are
first-class and fully featured. Python is also the most common scripting language among network and
cloud engineers, so the code stays easy to read and extend. The tool uses `click` for the CLI,
`rich` for readable tables and warning banners, and `pytest` for tests.

---

## 2. Architecture

```
            ┌────────────────────────────────────────────────────────────┐
  user ───► │ cli/        click commands, rendering, confirmations       │
            └──────────────┬─────────────────────────────────────────────┘
                           │  ChangePreview  (read-only "what would happen")
            ┌──────────────▼─────────────────────────────────────────────┐
            │ nsg/        manager   prepare_*()  ->  execute()  + audit  │
            │             planner   desired vs current  (+ ~ - =)        │
            │             serializer JSON <-> NsgConfig                  │
            │             search    filters                              │
            └──────┬──────────────────────────────┬──────────────────────┘
                   │                              │
   ┌───────────────▼──────────────┐  ┌────────────▼─────────────────────────┐
   │ validation/                   │  │ azure/                               │
   │  validators: fields, CIDR,    │  │  auth:   DefaultAzureCredential      │
   │              ports, priority  │  │  client: azure-mgmt-network wrapper  │
   │  analyzer:   duplicates,      │  │  errors: ARM error -> friendly error │
   │   conflicts, shadowing,       │  └────────────┬─────────────────────────┘
   │   security risks              │               │ HTTPS (ARM REST API)
   └───────────────────────────────┘               ▼
   models/  NsgRule, NsgConfig (pure dataclasses)   Azure Resource Manager
   utils/   settings (.env), JSON logging + redaction, audit log, error types
```

```
nsg-automation/
├── src/nsg_automation/
│   ├── main.py                 # console-script entry point (nsg-tool)
│   ├── __main__.py             # python -m nsg_automation
│   ├── azure/                  # auth.py, client.py, errors.py
│   ├── nsg/                    # manager.py, planner.py, serializer.py, search.py
│   ├── validation/             # validators.py, addressing.py, analyzer.py, issues.py
│   ├── cli/                    # app.py, output.py, prompts.py, interactive.py
│   ├── models/                 # rule.py, config.py
│   └── utils/                  # settings.py, logging_setup.py, audit.py, errors.py
├── config/
│   ├── example-nsg.json        # realistic web-tier NSG
│   └── example-dangerous.json  # shows the warnings/errors the tool catches
├── tests/                      # pytest suite (Azure fully mocked)
├── logs/                       # nsg-tool.log + audit.log (git-ignored)
├── .vscode/                    # launch configs, tasks, settings
├── .env.example
├── pyproject.toml / requirements.txt / requirements-dev.txt
└── LICENSE
```

**Key design decisions**

* **Every write has two steps.** First `prepare_*()` reads Azure, validates and analyses, and returns
  a `ChangePreview`. Then `execute()` performs the API call. `--dry-run` runs exactly the same code
  and stops before `execute()`, so what you preview is what would run.
* **Single-rule operations** use `SecurityRules.begin_create_or_update` and
  `SecurityRules.begin_delete`.
* **`apply` and `import` use one atomic PUT of the whole NSG**
  (`NetworkSecurityGroups.begin_create_or_update`). The tool reads the NSG, replaces its
  `securityRules` and PUTs it back, which is the same approach `az network nsg update` uses.
  This avoids half-applied states and allows priority swaps between rules, which would collide if
  the rules were updated one by one.
* **The SDK is isolated in `azure/client.py`.** Everything else works with `NsgRule`, so the tests
  replace Azure with an in-memory fake.

### Azure SDK / API approach

| Operation | SDK call | REST |
|---|---|---|
| Read NSG and rules | `network_security_groups.get` | `GET .../networkSecurityGroups/{nsg}` |
| Add/update rule | `security_rules.begin_create_or_update` | `PUT .../securityRules/{rule}` |
| Delete rule | `security_rules.begin_delete` | `DELETE .../securityRules/{rule}` |
| Create NSG / apply | `network_security_groups.begin_create_or_update` | `PUT .../networkSecurityGroups/{nsg}` |
| Default location | `resource_groups.get` (azure-mgmt-resource) | `GET .../resourceGroups/{rg}` |

Long-running operations are awaited with `poller.result()`, so the CLI reports the final
provisioning result. The SDK's built-in retry policy retries HTTP 429 and 5xx responses with
exponential back-off and honours `Retry-After`.

### NSG rule validation logic

**Field level** (`validation/validators.py`). All problems are reported together, not just the first.

| Field | Rule |
|---|---|
| priority | Integer from 100 to 4096. A lower number is evaluated first. Must be unique within the same direction. |
| name | 1–80 characters. Starts with a letter or digit, ends with a letter, digit or `_`. May contain `.`, `-` and `_`. |
| protocol | `Tcp`, `Udp`, `Icmp`, `Esp`, `Ah` or `*`. Case-insensitive; `any` is accepted. |
| ports | `*`, a single port (`443`), a range (`8000-8080`) or a list (`80,443`), all within 0–65535 with start ≤ end. `*` cannot be mixed with other values. |
| addresses | `*`, an IPv4/IPv6 address, strict CIDR (`10.0.0.5/24` is rejected with a "did you mean 10.0.0.0/24" hint), or a service tag (`Internet`, `VirtualNetwork`, `AzureLoadBalancer`, `Storage.WestEurope` ...). Service tags and `*` cannot be combined with other values. |
| description | 140 characters or fewer. |
| ASGs | Application Security Group resource IDs, used instead of address prefixes (not alongside them). |

**Rule-set level** (`validation/analyzer.py`). Azure evaluates inbound and outbound rules
separately, in ascending priority order, and the first match wins. The analyzer models that:

| Finding | Severity | Meaning |
|---|---|---|
| `PRIORITY_CONFLICT` | error | Two rules in the same direction share a priority. Azure would reject this. |
| `DUPLICATE_NAME` | error | The same name is used twice (names are case-insensitive). |
| `DUPLICATE_RULE` | warning | Identical match and action under a different name. |
| `REDUNDANT_RULE` | warning | Fully covered by an earlier rule with the same action, so it never matches. |
| `SHADOWED_RULE` | warning | Fully covered by an earlier rule with the *opposite* action, so it never takes effect. |
| `CONFLICTING_RULES` | warning | Partial overlap with the opposite action. The message says which rule wins. |
| `OVERRIDES_DEFAULT_RULES` | warning | A deny-all overrides `AllowAzureLoadBalancerInBound`, which breaks health probes. |

Overlap uses real CIDR and port-range math. Service-tag membership can't be known offline, so
comparisons that involve tags are reported only when the tool can be certain. This avoids false
alarms.

**Security** (Allow rules only):

| Finding | Severity |
|---|---|
| Any/Any inbound (`* / 0.0.0.0/0 → * → * → Allow`) | **CRITICAL**, needs confirmation |
| All ports open from the Internet | **CRITICAL**, needs confirmation |
| SSH, RDP, SMB, SQL, Redis, WinRM ... reachable from the Internet | **HIGH**, needs confirmation |
| Any/Any outbound | **HIGH**, needs confirmation |
| Wide port range (>1000) from the Internet | medium |
| Any source from the Internet (e.g. public HTTPS) | medium (informational) |

"From the Internet" means a source of `*`, `0.0.0.0/0`, `::/0` or `Internet`.

---

## 3. Prerequisites

* Python **3.10+** (tested with 3.11)
* Azure CLI (`az`), for the simplest sign-in. [Install guide](https://learn.microsoft.com/cli/azure/install-azure-cli)
* VS Code with the Python extension (recommended extensions are listed in `.vscode/extensions.json`)
* An Azure subscription and a resource group you have rights on

---

## 4. Azure permissions (RBAC)

Grant the **least privilege** at the **narrowest scope**, ideally the resource group that holds the
NSGs rather than the whole subscription.

| Commands | Built-in role |
|---|---|
| `list`, `search`, `export`, `plan`, `whoami` | **Reader** |
| `add`, `update`, `delete`, `apply`, `import`, `create-nsg` | **Network Contributor** |

For tighter control, create a custom role:

```json
{
  "Name": "NSG Rule Operator",
  "Description": "Manage NSGs and their security rules only.",
  "Actions": [
    "Microsoft.Network/networkSecurityGroups/read",
    "Microsoft.Network/networkSecurityGroups/write",
    "Microsoft.Network/networkSecurityGroups/securityRules/read",
    "Microsoft.Network/networkSecurityGroups/securityRules/write",
    "Microsoft.Network/networkSecurityGroups/securityRules/delete",
    "Microsoft.Resources/subscriptions/resourceGroups/read"
  ],
  "AssignableScopes": ["/subscriptions/<SUBSCRIPTION_ID>/resourceGroups/<RESOURCE_GROUP>"]
}
```

```powershell
az role definition create --role-definition nsg-operator-role.json
az role assignment create --assignee "<user-or-app-id>" --role "NSG Rule Operator" `
  --scope "/subscriptions/<SUBSCRIPTION_ID>/resourceGroups/<RESOURCE_GROUP>"
```

---

## 5. Installation

**Windows (PowerShell)**

```powershell
cd "nsg-automation"
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e ".[dev]"
nsg-tool --version
```

**Linux / macOS / Git Bash**

```bash
cd nsg-automation
python3 -m venv .venv
source .venv/bin/activate          # Git Bash on Windows: source .venv/Scripts/activate
pip install -e ".[dev]"
nsg-tool --version
```

If PowerShell blocks `Activate.ps1`, run
`Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once.

You can always run the tool without activating the venv: `.venv\Scripts\nsg-tool ...` or
`python -m nsg_automation ...`.

---

## 6. Azure authentication

The tool uses **`DefaultAzureCredential`** and never handles a password or secret itself. It tries
these sources in order and uses the first that works:

| # | Credential | When it applies |
|---|---|---|
| 1 | Environment | `AZURE_TENANT_ID` + `AZURE_CLIENT_ID` + `AZURE_CLIENT_SECRET` (or `AZURE_CLIENT_CERTIFICATE_PATH`). Typical for CI/CD service principals. |
| 2 | Workload Identity | AKS or GitHub Actions federated credentials |
| 3 | Managed Identity | Running on an Azure VM, App Service, Functions or Container Apps |
| 4 | Shared token cache | Windows developer token cache |
| 5 | VS Code | Azure Resources extension sign-in (requires `pip install azure-identity-broker`) |
| 6 | **Azure CLI** | `az login`. Recommended for interactive use. |
| 7 | Azure PowerShell | `Connect-AzAccount` |
| 8 | Azure Developer CLI | `azd auth login` |

The SDK fetches and refreshes tokens in memory. The tool only decodes non-secret claims (UPN or
app ID, object ID, tenant) so the audit log can record *who* made each change. Tokens are never
printed or logged.

**The subscription is resolved in this order:** `--subscription`, then `AZURE_SUBSCRIPTION_ID`
(environment or `.env`), then `subscriptionId` in the JSON file, then the Azure CLI default
(`az account show`).

### Test authentication: exact commands

```powershell
az login                                              # opens a browser (or: az login --use-device-code)
az account list --output table                        # find your subscription
az account set --subscription "<SUBSCRIPTION_ID>"
az account show --query "{name:name, id:id, user:user.name}" --output table
nsg-tool whoami                                       # proves the tool can get a token
```

Expected output:

```
Authenticated to Azure.
  Identity      alice@contoso.com
  Type          user
  Object ID     ...
  Tenant ID     ...
  Subscription  <SUBSCRIPTION_ID>
```

**Service principal (CI/CD).** Put these in the pipeline's secret store, never in git:

```powershell
$env:AZURE_TENANT_ID = "<tenant-id>"
$env:AZURE_CLIENT_ID = "<app-id>"
$env:AZURE_CLIENT_SECRET = "<secret>"          # or AZURE_CLIENT_CERTIFICATE_PATH
$env:AZURE_SUBSCRIPTION_ID = "<SUBSCRIPTION_ID>"
nsg-tool whoami
```

**Managed identity.** No configuration is needed on an Azure VM or App Service. For a
*user-assigned* identity, set `AZURE_CLIENT_ID` to its client ID.

---

## 7. Configuration

Copy `.env.example` to `.env` and edit it. `.env` is git-ignored.

```powershell
Copy-Item .env.example .env
```

| Variable | Purpose | Default |
|---|---|---|
| `AZURE_SUBSCRIPTION_ID` | Subscription to manage | `az account show` |
| `NSG_TOOL_LOG_DIR` | Folder for `nsg-tool.log` | `logs` |
| `NSG_TOOL_LOG_LEVEL` | Application log level | `INFO` |
| `NSG_TOOL_AUDIT_LOG` | Audit log path | `logs/audit.log` |
| `AZURE_TENANT_ID` / `AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET` | Optional service principal, read by `DefaultAzureCredential` | unset |

**Logs** are written as JSON lines:

* `logs/nsg-tool.log`: application and Azure SDK diagnostics.
* `logs/audit.log`: one entry per change attempt. Fields: `timestamp`, `user`, `action`,
  `subscription`, `resource_group`, `nsg`, `rule`, `operation`, `dry_run`, `result`
  (`success` / `failure` / `dry-run` / `aborted` / `blocked`), `error` and `details`
  (diffs, deleted rule contents, findings).

Values that look like tokens, secrets, passwords, JWTs or `Bearer` headers are redacted before
anything is written.

---

## 8. CLI commands

Global options go **before** the command: `nsg-tool [-s SUBSCRIPTION] [--env-file FILE] [--debug] COMMAND ...`.
Run `nsg-tool COMMAND --help` for full help on any command.

Multi-line examples use PowerShell's backtick (`` ` ``). In bash, use `\` instead.

### List and search

```powershell
nsg-tool list -g network-rg --nsg web-nsg
nsg-tool list -g network-rg --nsg web-nsg --direction inbound --include-defaults
nsg-tool list -g network-rg --nsg web-nsg -o json

# Which rules let 10.1.2.3 reach port 22?
nsg-tool search -g network-rg --nsg web-nsg --port 22 --source 10.1.2.3
nsg-tool search -g network-rg --nsg web-nsg --name "Allow-*" --access allow --direction inbound
nsg-tool search -g network-rg --nsg web-nsg --text "legacy" --min-priority 1000
```

### Create an NSG

```powershell
nsg-tool create-nsg -g network-rg --nsg web-nsg --location eastus --tag env=dev --tag owner=netops
```

### Add rules

```powershell
nsg-tool add `
  --resource-group network-rg `
  --nsg web-nsg `
  --name Allow-HTTPS `
  --direction inbound `
  --access allow `
  --protocol tcp `
  --source "*" `
  --source-port "*" `
  --destination "*" `
  --destination-port 443 `
  --priority 100 `
  --description "Allow HTTPS"

# Several prefixes/ports (comma-separated or repeat the option)
nsg-tool add -g network-rg --nsg web-nsg --name Allow-SSH-Admin --direction inbound --access allow `
  --protocol tcp --source "203.0.113.0/28,198.51.100.10" --destination 10.10.1.0/24 `
  --destination-port 22 --priority 200 --description "SSH from admin ranges"

# Outbound rule using a service tag
nsg-tool add -g network-rg --nsg web-nsg --name Allow-SQL-Out --direction outbound --access allow `
  --protocol tcp --source 10.10.1.0/24 --destination Sql.EastUS --destination-port 1433 --priority 100
```

`--source`, `--destination` and `--source-port` default to `*`. `--destination-port` is required
so that "any port" is always a deliberate choice.

### Update rules (only the options you pass change)

```powershell
nsg-tool update -g network-rg --nsg web-nsg --name Allow-HTTPS --destination-port "443,8443"
nsg-tool update -g network-rg --nsg web-nsg --name Allow-SSH-Admin --priority 210 --source 203.0.113.0/28
```

### Delete rules

```powershell
nsg-tool delete -g network-rg --nsg web-nsg --name Allow-SSH-Admin           # asks to confirm
nsg-tool delete -g network-rg --nsg web-nsg --name Allow-SSH-Admin --force   # scripts/CI
```

### Export, import, validate, plan and apply

```powershell
nsg-tool export -g network-rg --nsg web-nsg -f backups/web-nsg.json
nsg-tool validate config/example-nsg.json
nsg-tool plan     config/example-nsg.json
nsg-tool apply    config/example-nsg.json --dry-run
nsg-tool apply    config/example-nsg.json
nsg-tool import   backups/web-nsg.json            # create/update only, never deletes
```

| | `apply` | `apply --keep-unmanaged` | `import` |
|---|---|---|---|
| Creates rules from the file | ✔ | ✔ | ✔ |
| Updates rules that differ | ✔ | ✔ | ✔ |
| Deletes rules missing from the file | ✔ | ✘ | ✘ |
| Creates the NSG if it doesn't exist | ✔ | ✔ | ✔ |

### Interactive mode

```powershell
nsg-tool interactive
```

Interactive mode prompts for the resource group and NSG, then offers a menu: list, add, update,
delete, export, switch NSG. Each change offers a dry run first.

### Confirmations and `--force`

| Situation | Behaviour |
|---|---|
| Rule flagged CRITICAL or HIGH | Red **SECURITY WARNING** banner. You must type `yes`. |
| `delete`, or `apply` that deletes rules | Must confirm |
| `apply` / `import` | Shows the plan, then asks to confirm |
| Non-interactive shell (CI) without `--force` | **Aborted** (exit code 3). The tool never proceeds silently. |
| `--force` | Skips the prompts. The warnings are still displayed and audited. |
| Validation errors | Always blocked. `--force` cannot override them. |

### Exit codes

`0` success · `1` unexpected error · `2` invalid input/config · `3` aborted or not confirmed ·
`4` Azure error (auth, RBAC, not found, throttling, network) · `130` Ctrl+C

---

## 9. JSON configuration

```json
{
  "resourceGroup": "network-rg",
  "nsg": "web-nsg",
  "location": "eastus",
  "tags": { "environment": "dev" },
  "rules": [
    {
      "name": "Allow-HTTPS",
      "direction": "Inbound",
      "access": "Allow",
      "protocol": "Tcp",
      "source": "*",
      "sourcePort": "*",
      "destination": "*",
      "destinationPort": "443",
      "priority": 100,
      "description": "Allow HTTPS"
    },
    {
      "name": "Allow-SSH-Admin",
      "direction": "Inbound",
      "access": "Allow",
      "protocol": "Tcp",
      "source": ["203.0.113.0/28", "198.51.100.10"],
      "destination": "10.10.1.0/24",
      "destinationPort": "22",
      "priority": 200
    }
  ]
}
```

| Key | Required | Notes |
|---|---|---|
| `resourceGroup`, `nsg`, `rules` | yes | |
| `subscriptionId` | no | `--subscription` or the environment variable is preferred |
| `location`, `tags` | no | Used only if the NSG has to be created. Location defaults to the resource group's region. |
| rule `name`, `direction`, `access`, `protocol`, `priority`, `destinationPort` | yes | |
| rule `source`, `sourcePort`, `destination` | no | Default `*` |
| rule `sourceAsgs`, `destinationAsgs` | no | ASG resource IDs, used instead of `source`/`destination` |

* Address and port fields take a string (`"443"`, `"80,443"`) or a list.
* Azure property names (`sourceAddressPrefixes`, `destinationPortRanges` ...) are accepted as
  aliases.
* Unknown keys are errors, so typos such as `"prioirty"` are caught.
* `nsg-tool export` produces exactly this format, so export → edit → plan → apply is a round trip.

---

## 10. Dry-run example

```powershell
nsg-tool add -g network-rg --nsg web-nsg --name Allow-RDP --direction inbound --access allow `
  --protocol tcp --source Internet --destination-port 3389 --priority 150 --dry-run
```

```
┌──────────────────────────── NSG change ────────────────────────────┐
│ Operation       Add rule   [DRY RUN]                               │
│ Subscription    <SUBSCRIPTION_ID>                                  │
│ Resource group  network-rg                                         │
│ NSG             web-nsg                                            │
└────────────────────────────────────────────────────────────────────┘
──────────────────────── Existing configuration ───────────────────────
 Priority │ Name        │ Dir │ Access │ Proto │ Source │ ... │ Dst Port
 100      │ Allow-HTTPS │ Inb │ Allow  │ Tcp   │ *      │ ... │ 443
─────────────────────────── Proposed change ───────────────────────────
         + new rule
 Name               Allow-RDP
 Source             Internet
 Destination ports  3389  ...
──────────────────── Validation & security analysis ───────────────────
┌─────────────────────── !!  SECURITY WARNING  !! ──────────────────────┐
│ [HIGH] Allow-RDP: exposes sensitive port(s) 3389/RDP to the Internet  │
│     -> Use Azure Bastion, Just-In-Time VM access, a VPN, or restrict  │
│        the source to known admin IP ranges                            │
└───────────────────────────────────────────────────────────────────────┘
───────────────────────── Azure API operation ─────────────────────────
  SDK    : SecurityRules.begin_create_or_update
  HTTP   : PUT https://management.azure.com/subscriptions/.../networkSecurityGroups/web-nsg/securityRules/Allow-RDP
  Body   : { "name": "Allow-RDP", "properties": { "priority": 150, ... } }

DRY RUN: no changes were made to Azure.
```

---

## 11. Plan / apply example

```powershell
nsg-tool export -g network-rg --nsg web-nsg -f desired.json   # 1. start from what's deployed
#   ...edit desired.json in VS Code...
nsg-tool validate desired.json                                # 2. offline checks
nsg-tool plan desired.json                                    # 3. review the diff
nsg-tool apply desired.json                                   # 4. confirm and apply (one atomic PUT)
nsg-tool plan desired.json                                    # 5. should now say "No changes"
```

```
────────────────────── Plan for network-rg/web-nsg ──────────────────────
  - Legacy-FTP                       Inbound   300  Allow delete
  ~ Allow-HTTPS                      Inbound   100  Allow update
        Destination ports: 443  ->  443, 8443
  + Allow-HTTP-Redirect              Inbound   110  Allow create
  = Allow-SSH-Admin                  Inbound   200  Allow unchanged

Plan: 1 to create, 1 to update, 1 to delete, 1 unchanged.
```

For pipelines, use `nsg-tool plan desired.json -o json`. It produces a machine-readable diff that
includes the findings.

---

## 12. Testing

The test suite never touches Azure. Azure is replaced by an in-memory `FakeNsgClient` and by
`MagicMock` SDK clients.

```powershell
python -m pytest                                                      # all tests
python -m pytest -v tests/test_validators.py                          # one file
python -m pytest -k "dry_run or conflict"                             # by keyword
python -m pytest --cov=nsg_automation --cov-report=term-missing       # coverage
```

| File | Covers |
|---|---|
| `test_validators.py` | CIDR, ports, priority, protocol, names, description, full-rule building |
| `test_analyzer.py` | Overlap/coverage math, duplicates, conflicts, shadowing, priority collisions, security severities |
| `test_models_and_planner.py` | SDK model conversion (singular/plural fields, ASGs), rule comparison, plan create/update/delete/unchanged |
| `test_serializer.py` | JSON parsing, error aggregation, export → import round trip |
| `test_manager.py` | Dry-run is read-only, blocking rules, update merge, delete, atomic apply, audit entries |
| `test_azure.py` | SDK calls made with the correct arguments, Azure error → friendly error mapping |
| `test_cli.py` | End-to-end commands, `--dry-run`, confirmations and `--force`, plan/apply/import/export |
| `test_logging.py` | Secret redaction, audit fields |

---

## 13. Troubleshooting

| Message | Cause and fix |
|---|---|
| `No Azure subscription ID configured` | Run `az account set --subscription "<ID>"`, set `AZURE_SUBSCRIPTION_ID` in `.env`, or pass `-s <ID>`. |
| `Could not authenticate to Azure` | Run `az login`. Use `nsg-tool --debug whoami` to see every credential source that was tried. |
| `Access denied by Azure RBAC` | You need **Network Contributor** (writes) or **Reader** (reads) on the resource group. See [section 4](#4-azure-permissions-rbac). RBAC changes can take a few minutes to propagate. |
| `Subscription ... was not found` | Wrong ID, or the wrong tenant. Run `az account list -o table` and `az login --tenant <TENANT_ID>`. |
| `Resource group ... was not found` | Check the name with `az group list -o table`. |
| `Network security group ... was not found` | Check the NSG name, or create it with `nsg-tool create-nsg`. |
| `Rule ... was not found` | Rule names are case-insensitive. Check with `nsg-tool list`. |
| `priority N is used by multiple rules` | Pick a priority that's free in that direction. `nsg-tool list --direction inbound` shows the ones in use. |
| `has host bits set` | Use the network address that the error message suggests (e.g. `10.0.0.0/24`). |
| `Azure Resource Manager is throttling requests` | The SDK has already retried. Wait and re-run, and avoid running many instances in parallel. |
| `Could not reach Azure Resource Manager` | Check network access, proxy (`HTTPS_PROXY`) and DNS for `management.azure.com`. |
| `Confirmation required but the session is not interactive` | You're running in CI or with piped input. Review with `--dry-run`, then re-run with `--force`. |
| `MissingSubscriptionRegistration` | Run `az provider register --namespace Microsoft.Network`. |
| VS Code credential not used | Install `azure-identity-broker` and sign in through the Azure Resources extension, or just run `az login` in the integrated terminal. |

Use `--debug` for full stack traces and Azure SDK HTTP logs. Authorization headers are redacted by
the SDK. Everything is also written to `logs/nsg-tool.log`.

---

## 14. Security considerations

* **No credentials in code or config.** Authentication is entirely `DefaultAzureCredential`. `.env`,
  certificates and logs are git-ignored, and `.env.example` contains no secrets.
* **Least privilege.** Use Reader for read-only work and Network Contributor or the custom role in
  [section 4](#4-azure-permissions-rbac) for changes, scoped to the resource group.
* **Dangerous rules need explicit confirmation.** That includes Any/Any, all ports from the
  Internet, and management or database ports exposed to the Internet. They show a red banner and
  you must type `yes`; in CI they are refused unless you pass `--force`.
* **Destructive operations need confirmation** (deletes, and `apply` runs that remove rules).
* **`--force` is opt-in only.** It never bypasses validation errors, and forced changes are still
  audited with their findings.
* **Strict validation** of priorities, CIDRs (including host bits), ports, protocols, names and
  service-tag combinations, before any API call.
* **The audit trail** records who did what, where, when, and the result. Dry-runs and aborted
  attempts are recorded too.
* **Logs never contain secrets.** Keys and values that look like tokens, secrets, JWTs, `Bearer`
  headers or connection-string keys are redacted, and tokens are never printed.
* **Atomic bulk changes.** `apply` uses a single PUT, so a failure never leaves an NSG half-updated.
* **Concurrent edits.** `apply` replaces the whole rule set. If someone edits the NSG in the Portal
  between `plan` and `apply`, `apply` recomputes the plan from the live state, but run `plan`
  again if you need to review it first.

---

## 15. Example use cases

1. **Rules as code.** Keep `nsg/*.json` in git, review changes in pull requests, and have the
   pipeline run `nsg-tool plan file.json -o json` on the PR and `nsg-tool apply file.json --force`
   after merge.
2. **Security review of an existing NSG.** Run `nsg-tool export -g rg --nsg nsg -f current.json`,
   then `nsg-tool validate current.json`. This lists Internet-exposed RDP/SSH, shadowed rules,
   duplicates and priority problems.
3. **Incident response.** Block an attacker range immediately:
   `nsg-tool add ... --name Block-Attacker --access deny --source 198.51.100.0/24 --destination-port "*" --protocol "*" --priority 100`.
4. **Troubleshooting connectivity.** Ask "what allows or denies 10.1.2.3 on port 1433?" with
   `nsg-tool search -g rg --nsg nsg --source 10.1.2.3 --port 1433`.
5. **Standardising environments.** Apply the same baseline JSON to dev, test and prod NSGs, changing
   only `resourceGroup` and `nsg`.
6. **Backup and restore.** Run a scheduled `export` to keep a history. `apply` a previous export to
   roll back.
7. **Safe ad-hoc changes.** Run any `add`, `update` or `delete` with `--dry-run` first to see the
   exact REST call and its risks.

---

## 16. Running from VS Code

1. **File → Open Folder…** and choose `nsg-automation`. Install the recommended extensions when
   prompted.
2. Open a terminal (**Ctrl+`**), then create the venv and install (see [section 5](#5-installation)).
3. **Ctrl+Shift+P → "Python: Select Interpreter"** and choose `.venv`. This is already preset in
   `.vscode/settings.json`.
4. Copy `.env.example` to `.env` and set `AZURE_SUBSCRIPTION_ID`.
5. In the terminal, run `az login`, then `nsg-tool whoami`.
6. **Run and Debug (Ctrl+Shift+D)** offers ready-made launch configurations:
   * *nsg-tool: whoami (test auth)*
   * *nsg-tool: validate example config*
   * *nsg-tool: plan example config*
   * *nsg-tool: list (prompts for RG/NSG)*
   * *nsg-tool: interactive mode*
   * *pytest: all tests*

   You can set breakpoints anywhere, for example in `nsg/manager.py` or `validation/analyzer.py`.
7. **Testing panel (beaker icon)** discovers the pytest suite. Run or debug individual tests there.
8. **Terminal → Run Task** offers *Run tests*, *Tests with coverage* and *Validate example config*.

---

## Extending the tool

* **New security check:** add it to `security_issues()` in `validation/analyzer.py` and add a test
  in `tests/test_analyzer.py`.
* **New service tag:** add it to `KNOWN_SERVICE_TAGS` in `validation/addressing.py`. Unknown tags
  already produce a warning rather than an error.
* **New command:** add a `@cli.command()` in `cli/app.py`. Put any Azure calls in
  `azure/client.py` (and in `FakeNsgClient` for tests).

## License

MIT. See [LICENSE](LICENSE).
