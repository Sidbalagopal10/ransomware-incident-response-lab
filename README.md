\# Ransomware Incident Response \& Detection Engineering Lab



An end-to-end incident response investigation of a controlled ransomware-style intrusion against a Windows 11 endpoint, covering forensic reconstruction, containment, eradication, recovery, MITRE ATT\&CK mapping, and Sigma detection engineering.



> \*\*Safety:\*\* This project was conducted entirely in an isolated virtual lab using synthetic data. No real ransomware was executed, no real files were encrypted, and no data was transmitted to external systems.



\---



\## Project Overview



This project simulates the workflow of an Incident Response Analyst investigating a ransomware-style security incident.



Rather than focusing only on attack simulation, the project focuses on the defensive investigation:



\*\*What happened? How can it be proven from telemetry? How should the system be contained and recovered? What detections can be created from the observed behavior?\*\*



The investigation uses Windows endpoint telemetry and controlled network evidence to reconstruct activity across multiple stages of an incident.



\### Investigation Lifecycle



```text

Initial Execution

&#x20;      ↓

Discovery

&#x20;      ↓

Account Creation \& Privilege Modification

&#x20;      ↓

Data Collection \& Staging

&#x20;      ↓

Controlled Exfiltration

&#x20;      ↓

Ransomware-Like Impact

&#x20;      ↓

Containment

&#x20;      ↓

Eradication \& Recovery

&#x20;      ↓

Forensic Reconstruction

&#x20;      ↓

Detection Engineering

```



\---



\## Lab Architecture



```text

┌─────────────────────────────┐

│ Windows 11 Endpoint         │

│ WIN-O7S4P69OAEE             │

│ 192.168.64.12               │

│                             │

│ Sysmon                      │

│ Security Event Log          │

│ PowerShell Logging          │

└──────────────┬──────────────┘

&#x20;              │

&#x20;              │ Controlled Lab Traffic

&#x20;              │

&#x20;              ▼

┌─────────────────────────────┐

│ Kali Linux                  │

│ 192.168.64.11               │

│                             │

│ Controlled HTTP Server      │

│ Controlled Upload Receiver  │

└─────────────────────────────┘

```



The environment was hosted using isolated virtual machines. Network activity used only lab-controlled systems.



\---



\## Telemetry Sources



The investigation correlated evidence from:



\- Sysmon

\- Windows Security Event Log

\- PowerShell Operational Log

\- Windows filesystem artifacts

\- SHA256 cryptographic hashes

\- Kali Linux HTTP server logs

\- Kali Linux receiver logs



Cross-source correlation was used wherever possible instead of relying on a single telemetry source.



\---



\## Incident Narrative



\### Initial Execution



PowerShell retrieved a controlled test artifact from the Kali Linux system using `Invoke-WebRequest`.



Telemetry captured:



\- PowerShell process creation

\- Script Block execution

\- Network communication

\- File creation

\- Receiver-side HTTP activity



\### Discovery



A burst of reconnaissance commands enumerated:



\- Current user

\- Hostname

\- Network configuration

\- User privileges

\- Local accounts

\- Local administrator membership

\- ARP cache



Sysmon process relationships allowed the discovery activity to be correlated with a common PowerShell parent process.



\### Account Activity



A controlled local account named `IRLab\_Backup` was created and subsequently added to the local Administrators group.



Windows Security Event ID 4720 independently confirmed account creation.



Security Event ID 4732 was not observed, so administrator-group modification was established using process command-line telemetry and membership verification rather than claiming unavailable evidence.



\### Collection \& Staging



Three synthetic training documents were copied into a staging directory and compressed into:



`collected\_data.zip`



PowerShell Script Block Logging and Sysmon File Create telemetry captured the staging activity.



\### Controlled Exfiltration



The staged archive was transferred to the Kali lab host using an HTTP POST request.



Successful transfer was established through multiple evidence sources:



\- PowerShell upload command

\- Sysmon network connection

\- Receiver-side logging

\- Matching transfer size

\- Matching SHA256 hashes



\### Ransomware-Like Impact



Three controlled files were renamed with a `.locked` extension and a simulated ransom note was created.



The exercise deliberately did \*\*not\*\* perform real encryption.



Hash comparison showed that the affected files remained identical to known-good copies at the content level.



`vssadmin list shadows` was used only to inspect shadow-copy state. No shadow copies were deleted or modified.



\---



\## Containment, Eradication \& Recovery



Containment included:



\- Blocking inbound communication from the controlled remote host

\- Blocking outbound communication to the controlled remote host

\- Disabling the suspicious local account

\- Checking for active connections to the known remote system



Eradication removed the lab-created account.



Recovery restored the affected training files from known-good copies.



SHA256 verification confirmed that the recovered files matched their known-good versions.



\---



\## MITRE ATT\&CK Mapping



| Technique | ID |

|---|---|

| PowerShell | T1059.001 |

| Ingress Tool Transfer | T1105 |

| System Owner/User Discovery | T1033 |

| System Network Configuration Discovery | T1016 |

| Account Discovery: Local Account | T1087.001 |

| Permission Groups Discovery: Local Groups | T1069.001 |

| Create Account: Local Account | T1136.001 |

| Account Manipulation | T1098.007 |

| Data Staged: Local Data Staging | T1074.001 |

| Archive Collected Data | T1560.001 |

| Exfiltration Over C2 Channel | T1041 |



\### Evidence-Based Exclusions



\*\*T1486 – Data Encrypted for Impact\*\* was intentionally not claimed because the files were renamed rather than encrypted.



\*\*T1490 – Inhibit System Recovery\*\* was intentionally not claimed because shadow-copy state was queried but no recovery mechanism was deleted or modified.



\---



\## Detection Engineering



Five behavior-based Sigma rules were developed from activity observed during the investigation.



| Detection | Purpose |

|---|---|

| `powershell\_download.yml` | Detect PowerShell remote-download behavior |

| `local\_account\_creation.yml` | Detect local account creation using Windows account-management utilities |

| `local\_admin\_group\_add.yml` | Detect local Administrators group modification |

| `powershell\_compress\_archive.yml` | Detect PowerShell archive creation |

| `powershell\_http\_upload.yml` | Detect PowerShell HTTP POST file-upload behavior |



The rules focus on behavioral patterns rather than only hard-coded lab indicators.



\---



\## Sigma Validation



Rules were validated using \*\*Sigma CLI 3.1.0\*\*.



```text

Found 0 errors, 0 condition errors and 0 issues.

No rule errors found.

No condition errors found.

No validation issues found.

```



\*\*Result: PASS\*\*



The rules were additionally correlated with telemetry generated during the controlled incident.



Sigma validation confirms rule validity; it does not imply that the rules generated alerts in a production SIEM.



\---



\## Key Investigation Findings



\- A recurring PowerShell process provided a useful pivot across multiple incident stages.

\- Windows Security Event ID 4720 confirmed suspicious local-account creation.

\- Process telemetry established administrator-group modification even though Event ID 4732 was not available.

\- Data staging and archive creation were reconstructed from PowerShell and Sysmon telemetry.

\- Controlled exfiltration was confirmed using endpoint and receiver-side evidence plus cryptographic hashes.

\- File hashes proved that ransomware-like impact involved renaming rather than encryption.

\- Recovery mechanisms were queried but not destroyed.

\- Containment, eradication, and recovery were completed and verified.

\- Investigation findings were converted into reusable Sigma detection logic.



\---



\## Repository Structure



```text

Ransomware-IR-Lab/

│

├── README.md

├── .gitignore

│

├── detections/

│   ├── local\_account\_creation.yml

│   ├── local\_admin\_group\_add.yml

│   ├── powershell\_compress\_archive.yml

│   ├── powershell\_download.yml

│   └── powershell\_http\_upload.yml

│

├── docs/

│   └── incident-report.md

│

├── evidence/

│   ├── master-timeline.txt

│   ├── mitre-attack-mapping.txt

│   ├── ioc-and-artifacts.txt

│   ├── detection-coverage-matrix.txt

│   └── sigma-validation-results.txt

│

└── screenshots/

```



\---



\## Forensic Limitations



Timestamp inconsistencies were observed between Windows Event Viewer display times, embedded Sysmon UTC timestamps, and Kali Linux logs.



Original timestamps were preserved rather than silently normalized, and the discrepancy is documented as an investigative limitation.



The lab also intentionally excluded destructive ransomware behavior, credential theft, enterprise Active Directory infrastructure, and production SIEM deployment.



\---



\## Skills Demonstrated



\*\*Incident Response\*\*

\- Evidence collection

\- Timeline reconstruction

\- Process-tree analysis

\- Incident scoping

\- Containment

\- Eradication

\- Recovery

\- Integrity verification



\*\*Windows Security\*\*

\- Sysmon analysis

\- Windows Security Event analysis

\- PowerShell Script Block Logging

\- Process and command-line investigation

\- Windows Firewall containment



\*\*Detection Engineering\*\*

\- Sigma rule development

\- Behavioral detection design

\- Detection-to-evidence correlation

\- Sigma CLI validation

\- MITRE ATT\&CK mapping



\*\*Forensics\*\*

\- Cross-source event correlation

\- SHA256 verification

\- Artifact analysis

\- Evidence-based conclusions

\- Documentation of telemetry limitations



\---



\## Full Incident Report



The complete investigation is available in:



\[`docs/incident-report.md`](docs/incident-report.md)



Additional timelines, ATT\&CK mappings, detection coverage, artifacts, and validation results are available under:



\[`evidence/`](evidence/)



Sigma detection rules are available under:



\[`detections/`](detections/)



\---



\## Disclaimer



This repository documents a cybersecurity training exercise performed exclusively within a controlled virtual laboratory.



All hosts, accounts, files, network services, and incident artifacts used in the simulation were created for training purposes. No third-party systems were targeted and no real ransomware was deployed.

