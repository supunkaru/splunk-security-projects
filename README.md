# Splunk Security Projects

A hands-on cybersecurity portfolio focused on security monitoring, threat hunting, log analysis, and detection engineering using Splunk.

This repository documents practical projects designed to build skills in investigating suspicious activity, writing Splunk Search Processing Language (SPL) queries, analyzing security telemetry, and communicating findings clearly.

## Projects

### 01 - Windows Sysmon Threat Hunting

**Status:** In Progress

Investigating Windows endpoint telemetry using Sysmon logs and Splunk Enterprise to identify and analyze potentially suspicious activity.

**Investigation areas:**

- Process creation and parent child process relationships
- File creation and suspicious executable activity
- Network connections and potential command-and-control activity
- PowerShell execution and possible persistence mechanisms
- Windows Firewall registry modifications

**Tools:** Splunk Enterprise, Sysmon, SPL

**Data source:** LetsDefend training dataset. Dataset attribution and scope will be documented in the project.

[View Project 01](./01-windows-sysmon-threat-hunting/README.md)
