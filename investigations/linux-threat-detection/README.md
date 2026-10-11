# Linux Threat Detection — Authentication, Intrusion and Persistence Investigations

## Executive Summary

This project documents simulated Linux security investigations involving unauthorized SSH access, web application exploitation, suspicious command execution, cryptominer deployment, privilege escalation, and persistence.

The investigations used Linux authentication logs, Nginx access logs, auditd telemetry, and system configuration artifacts to identify attacker behavior and reconstruct suspicious activity.

The analysis covered three areas:

- **Initial access:** SSH password-guessing activity, successful root authentication, and command injection against a web application.
- **Post-compromise activity:** System and security-tool discovery, suspicious script execution, staging in temporary directories, internal SSH reconnaissance, and cryptominer-related execution.
- **Privilege escalation and persistence:** Reverse-shell activity, credential discovery, transition to root through `su`, and modifications involving systemd services, cron jobs, local accounts, and SSH authorized keys.

The objective was to distinguish suspicious commands from confirmed system events, correlate evidence across available log sources, and identify practical detection opportunities for Linux security monitoring.

The scenarios were completed in a controlled training environment. Findings from separate scenarios are documented independently and should not be interpreted as one continuous intrusion.

## Investigation Scope

The case study focuses on identifying and interpreting malicious or suspicious activity on Linux systems.

| Investigation Area | Activities Examined | Primary Evidence |
| --- | --- | --- |
| Initial Access | SSH authentication attacks, successful root login, web command injection, reverse-shell preparation | Authentication logs, Nginx logs, auditd |
| Discovery and Execution | System reconnaissance, security-tool discovery, temporary staging, internal SSH enumeration, cryptominer execution | auditd process and command telemetry |
| Privilege Escalation and Persistence | Reverse shell, credential discovery, `su root`, systemd, cron, account creation, authorized-key modification | auditd records, authentication activity, persistence configuration |

### Investigation Objectives

The investigations sought to answer the following questions:

1. What events indicated potentially unauthorized access?
2. Which users, source addresses, processes, and commands were involved?
3. Could related events be correlated to reconstruct attacker behavior?
4. Which observations established successful execution or authentication?
5. What evidence supported persistence or privilege escalation?
6. What additional telemetry would be needed to validate uncertain outcomes?
7. How could the findings be translated into effective SOC detections?

## Evidence Sources and Analysis Methodology

### Linux Authentication Logs

Authentication evidence was used to investigate suspicious SSH activity, failed and successful login attempts, and privilege changes.

Relevant fields included source IP addresses, usernames, authentication results, and session-related information.

Authentication success was distinguished from subsequent attacker actions; a valid login event alone does not establish every activity performed during that session.

### Nginx Access Logs

Web server logs provided visibility into suspicious requests targeting the simulated TryPingMe application.

The investigation examined request paths and parameters to identify indications of command injection.

Nginx logs recorded the requests received by the application, while auditd evidence was used where available to determine whether the application subsequently launched suspicious commands.

### auditd Process Telemetry

Linux audit records were used to reconstruct command execution and process relationships.

Important investigative fields included executable paths, command arguments, user identifiers, effective user identifiers, and process context.

These records were particularly valuable for identifying activity that followed initial access, including discovery commands, reverse-shell execution, and privilege escalation.

### System Configuration Artifacts

Persistence-related evidence included changes involving:

- systemd service configurations
- cron scheduling
- local user accounts
- SSH `authorized_keys` files

These mechanisms were examined to determine how an attacker could maintain access after the original session ended.

### Investigation Methodology

The analysis followed a consistent process:

| Step | Analyst Activity |
| --- | --- |
| Identify | Locate suspicious authentication, web, process, or configuration events |
| Pivot | Examine source addresses, accounts, commands, and process identifiers |
| Correlate | Connect related events using timestamps, sessions, and process context |
| Assess | Separate observed activity from inferred attacker objectives |
| Document | Preserve relevant commands, screenshots, and findings |
| Recommend | Identify detection opportunities and visibility improvements |

### Evidence Standards

Each conclusion was based on the available artifacts rather than assumed attacker success.

For example:

- A suspicious web request does not independently prove that command injection succeeded.
- A reverse-shell command does not necessarily prove that a connection was established.
- A successful root login confirms authentication but does not independently establish the preceding credential-attack method.
- Creation of a persistence configuration does not automatically prove that it was successfully invoked later.
- An observed file or executable name does not independently establish its full capabilities.

Where the preserved evidence did not demonstrate an outcome, the report identifies the behavior as attempted, suspected, or requiring additional verification.

## Investigation Organization

The report is organized into three sections corresponding to the original Linux Threat Detection scenarios:

1. **Initial Access:** SSH authentication

## Initial Access Investigations

### Scenario 1 — Suspicious SSH Authentication and Root Access

#### Investigation Context

The first scenario involved suspicious SSH authentication activity originating from the external IP address `91.224.92.79`.

The investigation focused on identifying repeated authentication failures, determining whether the activity resulted in a successful login, and establishing which Linux account was accessed.

The authentication pattern was consistent with an SSH password-guessing attempt targeting a privileged account.

#### SSH Authentication Analysis

Linux authentication logs were reviewed for failed SSH login attempts and subsequent successful authentication events.

The primary investigative indicators included:

| Indicator | Observation |
| --- | --- |
| Source IP | `91.224.92.79` |
| Targeted account | `root` |
| Service | SSH (`sshd`) |
| Suspicious behavior | Repeated authentication failures |
| Confirmed outcome | Successful root authentication |

![Failed SSH authentication attempts](evidence/01-ssh-failed-authentication.png)

*Figure 1 — Linux authentication logs showing repeated failed SSH password attempts against `root`, `roy`, and `user`, originating from multiple external IP addresses.*

Repeated failed authentication events can indicate password guessing, particularly when they target privileged accounts and originate from an unexpected external address.

However, authentication failures alone do not establish that credentials were compromised. The investigation therefore examined subsequent authentication events to identify a confirmed access outcome.

#### Successful Root Authentication

The preserved authentication evidence showed a successful SSH login to the `root` account from `91.224.92.79`.

![Successful SSH root authentication](evidence/02-ssh-root-authentication.png)

*Figure 2 — Authentication log confirming a successful password-based SSH login to `root` from `91.224.92.79:51555` on August 21, 2025, at 17:10:08 UTC.*

The failed-authentication evidence also recorded repeated attempts against `root` from `91.224.92.79` shortly before the successful login from the same source address.

This source-address and account correlation strengthens the assessment of a successful password-guessing sequence. However, the log evidence alone does not reveal the method by which the correct password was obtained or establish the full scope of post-login activity.

This provided stronger evidence than failed-login activity alone because it established that the system accepted authentication for the privileged account.

The sequence was consistent with a potential successful password-guessing attack.

However, a successful login following multiple failures does not independently establish that the same actor performed every attempt or that the correct password was obtained through brute force.

#### Analyst Assessment

**Assessment: Suspicious SSH authentication with confirmed root access.**

The combination of repeated authentication failures and successful privileged authentication warranted investigation for potential unauthorized access.

The evidence established successful root authentication from the identified source address. Additional session and command telemetry would be needed to determine what the authenticated user subsequently executed.

#### Detection Opportunities

- Detect repeated SSH authentication failures from a common source address.
- Monitor unsuccessful login attempts targeting `root` and other privileged accounts.
- Correlate repeated authentication failures with later successful SSH authentication.
- Alert on successful direct root logins from unexpected external addresses.
- Examine session activity following suspicious successful authentication to identify further compromise indicators.