# sentinel-hybrid-siem-lab
Hybrid SIEM lab: on-prem Windows Server and Linux onboarded to Microsoft Sentinel via Azure Arc, with custom KQL detections and PowerShell/Python automation.
# Sentinel Hybrid SIEM Lab

I built this lab to get hands-on with Microsoft Sentinel. Two VMs run on my laptop (one Windows Server, one Ubuntu), get connected to Azure with Azure Arc, and send their security logs to Sentinel. From there I wrote my own detection rules, attacked my own machines to test them, and wrote a couple of scripts to automate the testing and reporting.

My original plan was to run the VMs in Azure. My subscription had no quota for the VM size I picked, so I ran them locally and connected them with Arc instead. That ended up being the more interesting setup, since that's how on-prem servers get monitored by a cloud SIEM in real environments.

## Setup

```
Laptop (Ubuntu, KVM)
 ├── win-dc01   Windows Server 2022  ── Arc agent + Azure Monitor Agent ──┐
 └── lnx-web01  Ubuntu Server        ── Arc agent + Azure Monitor Agent ──┤
                                                                         ▼
                                     Log Analytics workspace (law-siem-lab)
                                                                         │
                                                         Microsoft Sentinel
                                                  (analytics rules → incidents)
```

- Both VMs are on the default libvirt NAT network, so nothing is exposed to the internet.
- Everything in Azure is in one resource group, `rg-siem-lab` (Central US), so it's easy to tear down.
- Sentinel is managed from the Defender portal. Microsoft is retiring the Sentinel experience in the Azure portal.

![Arc machines](screenshots/01-arc-machines.png)

## Getting the logs in

I installed the **Windows Security Events via AMA** and **Syslog via AMA** connectors and made a data collection rule for each VM:

- `dcr-windows-security`: Windows security events, "Common" set, into the `SecurityEvent` table
- `dcr-linux-syslog`: only the `auth` and `authpriv` facilities at INFO and up, into `Syslog`. I left everything else off to keep ingestion small.

Creating the rules installs the Azure Monitor Agent on the machines automatically. Failed logons weren't showing up on Windows at first, so I turned on failure auditing:

```powershell
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
```

![Syslog in Sentinel](screenshots/03-syslog-ingestion.png)
![Windows events in Sentinel](screenshots/04-windows-security-events.png)

## Detection rules

All three are scheduled rules that run every 5 minutes. The KQL is in `detections/sentinel/`.

| Rule | Triggers on | Severity | MITRE |
|---|---|---|---|
| Linux - SSH Brute Force Attempt | 5+ failed SSH passwords from one IP in 10 min | Medium | T1110 |
| Windows - Multiple Failed Logons | 5+ Event ID 4625 for one account in 10 min | Medium | T1110 |
| Windows - User Added to Administrators | Event ID 4732 for the Administrators group | High | T1098 |

Some notes on how I wrote them:

- The admin group rule matches the group's SID (`S-1-5-32-544`) instead of its name. The name can be renamed, but that SID is the same on every Windows machine.
- Syslog stores the whole SSH message as one string, so I pull the source IP and username out with regex in the query.
- For Windows failed logons I grouped by account instead of IP, because local logon failures log the IP as `-`.

## Testing

**Linux.** From my laptop I ran a loop of SSH logins with a fake user and blank passwords:

```bash
for i in {1..10}; do ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no fakeuser@<lnx-web01-ip> exit; done
```

**Windows.** `scripts/powershell/Invoke-AttackSimulation.ps1` does two things. It generates 10 failed logons against an account that doesn't exist, and it creates a temporary user, adds it to Administrators, waits a minute, then deletes it. It only runs on `win-dc01` unless you pass `-Force`, and it always removes the test user, even if it errors out partway.

```powershell
.\Invoke-AttackSimulation.ps1                  # both tests
.\Invoke-AttackSimulation.ps1 -Scenario AdminGroup
```

All three rules fired:

![Incidents](screenshots/05-incidents.png)

A few things I noticed:

- I ran the SSH test twice, and got two separate incidents for it. Alert grouping would merge those, and it's the first thing I'd tune.
- The Windows failed-logon incident was for the built-in `Administrator` account. That came from my own wrong-password attempts at the VM's login screen, not from the script, so the rule caught activity I didn't stage for it.

## Python report

`scripts/python/sentinel_report.py` queries the workspace with the Azure Monitor Query SDK and prints a summary. It shows which hosts are still sending logs, the incidents, the SSH and Windows failed logins (flagging anything over the rule thresholds), and any Administrators group changes. It also saves the report as a Markdown file.

```bash
cd scripts/python
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env    # put your workspace ID in here
az login
python sentinel_report.py --hours 24
```

It signs in with your `az login` session, so there are no keys in the code.

![Report output](screenshots/07-python-report.png)

## Problems I ran into

- **No VM quota.** The new subscription had 0 cores allowed for the B-series v2 VMs in Central US. Instead of waiting on a quota request, I switched to local VMs with Azure Arc.
- **Arc onboarding sign-in kept failing.** The onboarding script uses a device-code sign-in, which my tenant blocks. I created a service principal with only the "Azure Connected Machine Onboarding" role, scoped to the lab resource group, with a secret that expired in a day. I deleted the secret once both machines were connected.
- **Wrong secret.** My first attempt failed with `AADSTS7000215` because I'd copied the secret's ID instead of its value.
- **Bad hostname.** The Windows VM joined Arc as `WIN-0H3FMF513V7`. I disconnected it, renamed it to `win-dc01`, and reconnected it before collecting any logs, so all the data has the right name.
- **Sentinel menus missing.** After connecting the workspace to the Defender portal, the Sentinel menus took a while to show up.
- **Expensive image.** The first Windows image I picked was a third-party marketplace image estimated at over $1,100 a month. I caught it on the cost estimate before deploying.

## What I'd add next

- Alert grouping to stop the duplicate incidents
- A playbook that emails me when a High incident is created
- More rules: security log cleared (1102), new service installed (7045), and a successful login right after a burst of failures
- Promoting `win-dc01` to a domain controller and adding AD-specific detections

## Repo layout

```
detections/sentinel/      KQL for the three analytics rules
scripts/powershell/       Invoke-AttackSimulation.ps1
scripts/python/           sentinel_report.py, requirements.txt, .env.example
screenshots/
```
