\# IR-LAB-2026

\## Ransomware Incident Response Investigation



\*\*Case ID:\*\* IR-LAB-2026  

\*\*Investigation Type:\*\* Controlled Ransomware Incident Response Simulation  

\*\*Role:\*\* Incident Response Analyst  

\*\*Affected System:\*\* WIN-O7S4P69OAEE  

\*\*Affected Host IP:\*\* 192.168.64.12  

\*\*Controlled Remote Host:\*\* 192.168.64.11  

\*\*Environment:\*\* Isolated Windows 11 / Kali Linux Virtual Lab  



\---



\## Executive Summary



IR-LAB-2026 was a controlled ransomware incident response simulation designed to reproduce and investigate a multi-stage intrusion against a Windows 11 endpoint.



The investigation reconstructed activity spanning PowerShell-based execution, system and account discovery, creation of a suspicious local account, addition of that account to the local Administrators group, collection and staging of controlled data, HTTP-based transfer to a lab-controlled remote host, and ransomware-like impact.



Endpoint and network evidence was collected from Sysmon, Windows Security Event Logs, PowerShell Operational logs, and Kali Linux receiver logs. Correlation of these sources allowed the activity to be reconstructed from initial execution through containment and recovery.



Controlled exfiltration was confirmed through PowerShell execution evidence, Sysmon network telemetry, receiver-side logging, transfer size, and matching SHA256 hashes between the source and received archive.



The ransomware-impact phase was intentionally non-destructive. Three synthetic training files were renamed with a `.locked` extension and a simulated ransom note was created. File-content hashes demonstrated that the files were not encrypted or modified. Recovery mechanisms were queried but were not deleted or modified.



Containment consisted of Windows Firewall rules blocking communication with the controlled remote host and disabling the suspicious local account. Eradication subsequently removed the account, and known-good copies of affected files were restored. SHA256 verification confirmed successful recovery.



Following the investigation, five behavior-based Sigma detection rules were developed for behaviors observed during the incident. All five rules successfully passed Sigma CLI 3.1.0 validation with zero rule errors, zero condition errors, and zero validation issues.



This exercise demonstrates an end-to-end incident response workflow encompassing evidence collection, forensic reconstruction, containment, eradication, recovery, MITRE ATT\&CK mapping, artifact analysis, and detection engineering.



\---



\## 1. Incident Overview



The simulated incident affected a Windows 11 endpoint named `WIN-O7S4P69OAEE` with lab IP address `192.168.64.12`. A Kali Linux system at `192.168.64.11` represented the controlled remote system.



The activity was deliberately generated within an isolated virtual lab using synthetic files and controlled network communication. No real ransomware, credential theft, destructive recovery inhibition, or external data exfiltration was performed.



The investigation sought to answer five primary questions:



1\. What activity occurred on the affected endpoint?

2\. How did the activity progress across the incident lifecycle?

3\. Was controlled data successfully transferred from the endpoint?

4\. What containment, eradication, and recovery actions were required?

5\. What detection opportunities could be derived from the observed behavior?



\---



\## 2. Investigation Scope



The investigation covered:



\- PowerShell execution and remote file retrieval

\- System, network, account, and privilege discovery

\- Local account creation

\- Local administrator group modification

\- Collection and staging of synthetic data

\- Archive creation

\- Controlled HTTP data transfer

\- Ransomware-like file impact

\- Recovery-mechanism reconnaissance

\- Network and account containment

\- Account eradication

\- File restoration and integrity verification

\- MITRE ATT\&CK mapping

\- Indicator and artifact analysis

\- Sigma detection engineering and validation



The investigation relied primarily on Sysmon, Windows Security Event Logs, PowerShell Operational logs, filesystem artifacts, cryptographic hashes, and receiver-side network logs.



\---



\## 3. Safety and Ethical Boundaries



All activity described in this report occurred within a controlled cybersecurity training environment.



Only synthetic training data was used. Network communication was restricted to lab-controlled virtual machines. No external systems were targeted.



The ransomware-like impact phase did not execute ransomware or encrypt data. Impact was simulated by renaming three controlled training files and creating a training ransom note.



No shadow copies were deleted, no recovery mechanisms were disabled, and no destructive commands were executed.



The project was designed to reproduce observable incident-response telemetry while minimizing destructive or unsafe behavior.


---

## 4. Reconstructed Attack Narrative

### 4.1 Initial Access and PowerShell Execution

The first observed activity involved PowerShell retrieving a controlled test artifact from the Kali Linux host.

PowerShell executed an `Invoke-WebRequest` request to:

`http://192.168.64.11:8080/beacon.txt`

and stored the response as:

`C:\IR-Lab\Files\beacon.txt`

The downloaded file contained the controlled string `IR-LAB-C2-CHECK`.

Sysmon Process Create telemetry identified the download process as `powershell.exe`, PID 1548, running with High integrity. The process was launched by an existing PowerShell process, PID 9388.

PowerShell Script Block Logging independently captured the `Invoke-WebRequest` command. Sysmon File Create telemetry recorded creation of `beacon.txt`, while network telemetry and the Kali HTTP server log confirmed communication between the Windows endpoint and `192.168.64.11:8080`.

The SHA256 hash of the downloaded artifact was:

`8CC79D8FEB356342C72A989FCAE4A80F363B457DF708C527D143D9DB8E7729FA`

This activity established the first observable execution and remote communication in the incident.

### 4.2 Discovery

Following initial execution, a sequence of host-discovery commands was observed:

- `whoami`
- `hostname`
- `ipconfig /all`
- `whoami /priv`
- `net user`
- `net localgroup administrators`
- `arp -a`

Sysmon process telemetry showed that these commands originated from the same parent PowerShell process, PID 9388.

The activity enumerated the current user, hostname, network configuration, user privileges, local accounts, local administrator membership, and ARP cache.

The concentrated sequence of reconnaissance commands represented a distinct discovery phase and provided a useful behavioral detection opportunity.

### 4.3 Account Creation and Privilege Modification

A new lab-controlled local account named `IRLab_Backup` was created using `net user`.

Windows Security Event ID 4720 confirmed creation of the account. Sysmon telemetry additionally recorded execution of `net.exe` and its child `net1.exe`.

The account was subsequently added to the local `Administrators` group using:

`net localgroup administrators IRLab_Backup /add`

A corresponding Security Event ID 4732 was not observed in the collected evidence. Therefore, administrator-group modification was established using Sysmon command-line telemetry and subsequent membership verification rather than claiming unavailable Security Event evidence.

The account was created solely for the controlled simulation and was never used for interactive logon.

### 4.4 Data Collection and Staging

Three synthetic training files were copied into:

`C:\IR-Lab\Staging`

The files represented controlled financial, payroll, and customer information.

PowerShell Script Block Logging captured the copy operations and subsequent archive creation using `Compress-Archive`.

The staged files were compressed into:

`C:\IR-Lab\Staging\collected_data.zip`

The archive size was 560 bytes and its SHA256 hash was:

`D62DF6CE434E4206E6CEA6D3F012E9DAC43AC506D322ADD502295136BB6632F5`

Sysmon File Create telemetry independently recorded creation of the staged files and resulting ZIP archive.

### 4.5 Controlled Exfiltration

The staged archive was transferred from the Windows endpoint to the controlled Kali Linux system using an HTTP POST request.

PowerShell executed an `Invoke-WebRequest` command using `-Method POST` and `-InFile` to transmit `collected_data.zip` to:

`http://192.168.64.11:8080/upload`

PowerShell Script Block Logging captured the complete upload command.

Sysmon network telemetry recorded a TCP connection from:

`192.168.64.12`

to:

`192.168.64.11:8080`

The Kali receiver independently recorded receipt of 560 bytes from the Windows endpoint and returned the controlled response `IR-LAB-UPLOAD-OK`.

SHA256 verification of the received archive matched the source archive:

`D62DF6CE434E4206E6CEA6D3F012E9DAC43AC506D322ADD502295136BB6632F5`

The combination of endpoint command telemetry, network telemetry, receiver-side logging, matching transfer size, and matching cryptographic hashes confirmed that the controlled archive was successfully transferred.

### 4.6 Ransomware-Like Impact

Ransomware-like impact was simulated without executing ransomware or encrypting data.

The three controlled training files were renamed:

- `financial_report.txt` → `financial_report.txt.locked`
- `payroll.txt` → `payroll.txt.locked`
- `customers.txt` → `customers.txt.locked`

A simulated ransom note was created at:

`C:\IR-Lab\Files\README_RESTORE_FILES.txt`

The note explicitly identified itself as an IR-LAB training artifact and requested no payment.

Hash comparison between the renamed files and known-good recovery copies produced exact matches. This demonstrated that file contents had not been encrypted or otherwise modified.

The command `vssadmin list shadows` was executed only to query shadow-copy state. No shadow copies were deleted and no recovery mechanisms were modified.

Accordingly, the investigation does not classify this activity as successful data encryption or recovery inhibition.

---

## 5. Forensic Timeline

| Phase | Local Time | Key Activity |
|---|---|---|
| Initial Execution | 18:19:43 | PowerShell retrieves `beacon.txt` |
| Initial Execution | 18:19:44 | Controlled beacon artifact created |
| Discovery | 18:28:04 | `whoami` executed |
| Discovery | 18:28:13 | Hostname discovery |
| Discovery | 18:28:23 | Network configuration discovery |
| Discovery | 18:28:35 | Privilege discovery |
| Discovery | 18:28:50 | Local account discovery |
| Discovery | 18:29:01 | Administrator-group discovery |
| Discovery | 18:29:16 | ARP cache discovery |
| Account Activity | 18:39:37 | `IRLab_Backup` account creation confirmed |
| Account Activity | ~18:39:50 | Account added to local Administrators group |
| Staging | 18:51:52 | Staging directory created |
| Staging | 18:52:03–18:52:04 | Controlled documents staged |
| Staging | 18:52:16 | `collected_data.zip` created |
| Exfiltration | 19:03:33 | HTTP POST of staged archive initiated |
| Impact | 19:11:13–19:11:14 | Controlled files renamed `.locked` |
| Impact | 19:11:32 | Simulated ransom note created |
| Impact | 19:12:02 | Shadow-copy state queried |
| Containment | 19:17:10–19:19:19 | Firewall isolation and account containment |
| Eradication | After containment | `IRLab_Backup` removed |
| Recovery | After eradication | Known-good files restored and hash verified |

### 5.1 Timestamp Limitation

Timestamp inconsistencies were observed among Windows Event Viewer display times, embedded Sysmon UTC timestamps, and Kali Linux logs.

For example, some Sysmon events contained embedded UTC values that did not align consistently with the corresponding Event Viewer local display time. The discrepancy was not silently corrected.

Original timestamps were preserved as collected, and the primary timeline above uses Windows Event Viewer local times where available. Cross-source timestamp differences are treated as a documented forensic limitation.

This demonstrates the importance of time synchronization and timezone normalization when correlating telemetry from multiple systems.

---

## 6. Containment

Containment focused on preventing further communication with the controlled remote host and neutralizing the suspicious account.

Two Windows Firewall rules were created to block traffic associated with `192.168.64.11`:

- Outbound communication to the controlled remote host was blocked.
- Inbound communication from the controlled remote host was blocked.

The `IRLab_Backup` account was then disabled.

Verification confirmed that the firewall rules were enabled and configured with a blocking action. Account inspection confirmed that `IRLab_Backup` was inactive and had never logged on.

No active TCP connections to the known remote host were observed during containment verification.

A subsequent connectivity test to TCP port 8080 failed. However, because the Kali listener had also been stopped, the failed connection test alone was not treated as proof of firewall effectiveness. The firewall configuration itself provided independent evidence that explicit blocking controls had been applied.

The containment process was completed in approximately two minutes and nine seconds.

---

## 7. Eradication and Recovery

Following containment, the suspicious `IRLab_Backup` account was deleted.

A subsequent account query returned that the username could not be found, confirming removal.

The three `.locked` training artifacts were removed and replaced using the known-good copies previously preserved in:

`C:\IR-Lab\Recovery`

SHA256 verification was performed following restoration.

Recovered hashes matched the known-good values:

| File | SHA256 |
|---|---|
| `financial_report.txt` | `6AD63859691ADED0871FB377788D8BD046183E8376E228BCD4EBCE769833BED1` |
| `payroll.txt` | `523BDDDEF2A6DAB21DCD60193F08FACDE0F375AB1A7D617292DBD4119560DE82` |
| `customers.txt` | `2F4DB1CB6270589F34AAA8E0D6A208ADC05CA79C69F380F8EC61DA60A59E4942` |

Matching hashes demonstrated successful restoration of the controlled files and confirmed that their contents were identical to the known-good recovery copies.

---

## 8. Indicators and Investigative Artifacts

The investigation identified several host, network, account, process, and filesystem artifacts useful for reconstructing the incident.

| Category | Artifact | Significance |
|---|---|---|
| Affected Host | `WIN-O7S4P69OAEE` | Windows 11 endpoint investigated |
| Affected IP | `192.168.64.12` | Source of controlled incident activity |
| Remote Lab Host | `192.168.64.11` | Kali Linux system used as controlled remote host |
| Network Service | TCP `8080` | Used for controlled download and upload activity |
| Download Path | `/beacon.txt` | Initial controlled HTTP retrieval |
| Upload Path | `/upload` | Controlled archive transfer endpoint |
| Suspicious Account | `IRLab_Backup` | Lab-created local administrative account |
| Recurring Process | `powershell.exe`, PID 9388 | Major investigative pivot across multiple phases |
| Process GUID | `{4c666344-fa01-6ac2-e400-000000000900}` | Correlated recurring PowerShell activity |
| Downloaded Artifact | `C:\IR-Lab\Files\beacon.txt` | Controlled remote retrieval artifact |
| Staging Directory | `C:\IR-Lab\Staging` | Local collection/staging location |
| Archive | `collected_data.zip` | Controlled staged-data archive |
| Archive SHA256 | `D62DF6CE434E4206E6CEA6D3F012E9DAC43AC506D322ADD502295136BB6632F5` | Used to verify controlled transfer |
| Ransom Note | `README_RESTORE_FILES.txt` | Simulated ransomware-impact artifact |
| File Extension | `.locked` | Controlled impact indicator |

These indicators are **lab-generated investigative artifacts**, not real-world threat-intelligence indicators and should not be treated as indicators associated with an actual malware family or threat actor.

---

## 9. MITRE ATT&CK Mapping

Observed behaviors were mapped to relevant MITRE ATT&CK techniques where supported by collected evidence.

| Technique | ID | Evidence |
|---|---|---|
| PowerShell | T1059.001 | PowerShell used throughout execution and incident activity |
| Ingress Tool Transfer | T1105 | Controlled `beacon.txt` retrieved from remote lab host |
| System Owner/User Discovery | T1033 | `whoami` |
| System Network Configuration Discovery | T1016 | `ipconfig /all` and network reconnaissance |
| Account Discovery: Local Account | T1087.001 | `net user` |
| Permission Groups Discovery: Local Groups | T1069.001 | `net localgroup administrators` |
| Create Account: Local Account | T1136.001 | Creation of `IRLab_Backup` |
| Account Manipulation | T1098.007 | Addition of lab account to local Administrators group |
| Data Staged: Local Data Staging | T1074.001 | Controlled files copied into staging directory |
| Archive Collected Data | T1560.001 | `Compress-Archive` used to create ZIP archive |
| Exfiltration Over C2 Channel | T1041 | Controlled HTTP transfer to remote lab system |

Two techniques were intentionally **not** claimed.

**Data Encrypted for Impact (T1486)** was not assigned because file-content hashes demonstrated that the affected files were renamed rather than encrypted.

**Inhibit System Recovery (T1490)** was not assigned because `vssadmin list shadows` only queried shadow-copy state. No shadow copies or recovery mechanisms were deleted, disabled, or modified.

This conservative mapping approach avoids assigning ATT&CK techniques that are not supported by the collected evidence.

---

## 10. Detection Engineering

Following investigation of the incident, five behavior-based Sigma detection rules were developed.

### 10.1 PowerShell Remote Download

**Rule:** `powershell_download.yml`

Detects PowerShell or PowerShell Core execution involving `Invoke-WebRequest` or its common alias in combination with output-to-file behavior.

Primary ATT&CK mappings:

- T1059.001 — PowerShell
- T1105 — Ingress Tool Transfer

### 10.2 Local Account Creation

**Rule:** `local_account_creation.yml`

Detects execution of `net.exe` or `net1.exe` containing account-management syntax associated with creation of a local user.

Primary ATT&CK mapping:

- T1136.001 — Create Account: Local Account

### 10.3 Local Administrator Group Modification

**Rule:** `local_admin_group_add.yml`

Detects `net.exe` or `net1.exe` command-line activity involving the local Administrators group and account addition.

The rule was based on process telemetry because Security Event ID 4732 was not observed in the collected dataset.

### 10.4 PowerShell Archive Creation

**Rule:** `powershell_compress_archive.yml`

Detects PowerShell Script Block activity containing `Compress-Archive`.

Primary ATT&CK mapping:

- T1560.001 — Archive Collected Data

### 10.5 PowerShell HTTP Upload

**Rule:** `powershell_http_upload.yml`

Detects PowerShell Script Block activity combining:

- `Invoke-WebRequest`
- HTTP POST behavior
- `-InFile`

Primary ATT&CK mapping:

- T1041 — Exfiltration Over C2 Channel

The rules were intentionally designed around observable behaviors rather than hard-coding only the lab IP addresses, filenames, or account name. This improves their usefulness beyond the exact simulation.

---

## 11. Detection Validation

The five custom Sigma rules were validated using:

`Sigma CLI 3.1.0`

The validation command was:

`sigma check *.yml`

The final result was:

```text
Found 0 errors, 0 condition errors and 0 issues.
No rule errors found.
No condition errors found.
No validation issues found.
