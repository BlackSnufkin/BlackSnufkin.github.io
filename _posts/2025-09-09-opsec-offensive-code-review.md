---
title: "OPSEC: Read the Code Before It Burns Your Op"
date: 2025-09-07 13:00:00 +0300
categories: [OPSEC]
tags: [OPSEC, Detection, IOCs]
---


Hardcoded constants in offensive tools become detection signatures. Static strings that seem harmless during development persist in logs, network traffic, and file systems, creating reliable indicators for defensive teams.

This analysis examines specific examples from commonly used tools and outlines a review methodology to identify these issues before operational use.

---

## Detection Through Static Artifacts

Defense systems increasingly rely on stable identifiers embedded in tools rather than behavioral patterns. Process names, pipe identifiers, domain values, and template content provide high-confidence detection opportunities when they remain constant across deployments.

These artifacts appear in Windows event logs, network monitoring, file forensics, and cloud audit trails. Once cataloged, they enable retrospective analysis and cross-campaign attribution.

---

## Tool Analysis

### Rubeus: LSA Process Name (Historical)

Rubeus is a C# toolset for Kerberos interaction and attacks. It handles authentication operations through the Local Security Authority (LSA) interface.

Earlier versions registered with the Local Security Authority using a non-standard process name:

![](/assets/posts/2025-09-09-OPSEC-OFFENSIVE-CODE-REVIEW/rubeus-typo.png)

The legitimate Windows process name is `User32LogonProcess`. Those versions used `User32LogonProcesss` with an additional 's', creating a unique identifier that appeared in authentication events (Event ID 4624/4634) on every target system.

This deviation from the documented LSA interface made Rubeus activity distinguishable from legitimate authentication processes. This has been addressed in current versions.

**Signature Propagation**: The same typo appears in [KrbRelayUp](https://github.com/Dec0ne/KrbRelayUp), a local privilege escalation tool that leverages Kerberos relay attacks. KrbRelayUp inherited this identifier when implementing similar LSA functionality, demonstrating how detection signatures propagate across tools when developers reuse code without reviewing for operational security implications.

This creates a shared IOC between two distinct tools, allowing defenders to attribute activity to either Rubeus (historical versions) or KrbRelayUp through the same authentication log signature.

### NetExec: Search Connector Module

NetExec is a network execution tool for penetration testing with various attack modules. The `drop-sc` module implements a technique for lateral movement using Windows Search Connectors.

The `drop-sc` module generates Windows Search Connector files containing hardcoded URL values:

![](/assets/posts/2025-09-09-OPSEC-OFFENSIVE-CODE-REVIEW/nxc-rickroll.png)


Each generated `.searchConnector-ms` file embeds this default URL in its XML structure unless explicitly overridden. File analysis immediately identifies the tool and technique through this constant.

### Mimikatz: Golden Ticket Domain (Historical)

Mimikatz is a post-exploitation tool for credential extraction and Kerberos manipulation. The golden ticket functionality allows creation of forged Kerberos tickets.

Previous versions used a static domain in golden ticket generation. The problematic code appeared in the validation info structure:

![](/assets/posts/2025-09-09-OPSEC-OFFENSIVE-CODE-REVIEW/mimikatz-ansi.png)

This hardcoded domain `<3 eo.oe ~ ANSSI E>` appeared in Kerberos authentication logs for every generated ticket using default parameters. The string became a reliable detection signature in Windows Security logs before being addressed in later releases.

### Impacket: Named Pipe Implementation

Impacket is a Python library for network protocol implementation. The psexec module provides remote command execution capabilities similar to Microsoft's PsExec tool.

The psexec module creates named pipes with consistent patterns and contains a spelling error:

![](/assets/posts/2025-09-09-OPSEC-OFFENSIVE-CODE-REVIEW/impacket-typo.png)

The primary communication pipe uses "communicaton" instead of "communication". This identifier appears in named pipe creation events and SMB traffic analysis, providing definitive tool attribution.

### ROADtools: Device Authentication Domain

ROADtools is a framework for Azure AD security research and testing. The `DeviceAuthentication` class handles device registration and Primary Refresh Token (PRT) operations for Azure AD environments.

During device registration, the code hardcodes a target domain:

![](/assets/posts/2025-09-09-OPSEC-OFFENSIVE-CODE-REVIEW/roadtool_domain.png)

This domain appears in Azure enrollment logs, cloud audit trails, and device management systems, linking operations across organizations. The static domain becomes a persistent identifier that connects ROADtools usage across different engagements and target environments.

### AADInternals: Device Attributes

AADInternals is a PowerShell module for Azure Active Directory and Office 365 security testing. This code handles Intune MDM device enrollment and callback functionality.

The `Start-DeviceIntuneCallback` function simulates device communication with Microsoft Intune, sending device status and configuration information.

Within the device settings, a fixed phone number appears:

![](/assets/posts/2025-09-09-OPSEC-OFFENSIVE-CODE-REVIEW/aadinternals-phonenum.png)

This value persists in Intune/MDM logs, device registration events, and SyncML communication records, creating a consistent tracking identifier.

### Huan: PE Section Naming

Huan is a PE file packer that encrypts executables and stores them in new PE sections. The tool provides file protection capabilities for avoiding static analysis.

The packer creates PE sections with a static name:

![](/assets/posts/2025-09-09-OPSEC-OFFENSIVE-CODE-REVIEW/huan-section.png)

All processed executables contain this section name, making them identifiable through standard PE analysis tools and automated malware scanning systems.

---

## Source Review Methodology

### Configuration Analysis

Identify all user-configurable parameters. Trace their usage to confirm they override hardcoded values in output artifacts. Many tools accept configuration changes but still embed static values in specific contexts.

### Output Mapping

Document every external artifact generated by the tool: files, registry entries, network traffic, log messages, and process names. Verify that identifiable content can be customized or randomized.

### Template Review

Examine code that builds structured output (XML, JSON, binary formats). Look for hardcoded field values that should vary based on target environment or operational requirements.

### Network Protocol Implementation

Check protocol handlers for static identifiers in headers, user agents, pipe names, service descriptions, and other transmitted metadata.

### Error and Debug Content

Review error messages, debug output, and status information for embedded tool names, version strings, or developer identifiers that could appear in logs.

---

## Current and Historical Detection Signatures

Active and historical tool identifiers:

- **Rubeus** (historical): `User32LogonProcesss` in Windows authentication logs

- **NetExec**: `https://rickroll` in search connector file content

- **Mimikatz** (historical): `<3 eo.oe ~ ANSSI E>` in Kerberos ticket domains

- **Impacket**: `\RemCom_communicaton` in named pipe creation events

- **ROADtools**: `iminyour.cloud` in Azure device enrollment logs

- **AADInternals**: `"1234567890"` in device management records

- **Huan**: `.huan` in PE section headers

These signatures enable both real-time detection and historical analysis of tool usage patterns. While some issues have been resolved, the detection patterns demonstrate how hardcoded values become lasting operational signatures.

---

## Bonus: When the Hunters Become the Hunted

While searching GitHub for `cve-2025-44228` PoCs, I encountered several malicious repositories targeting security researchers through weaponized project files. These attacks exploit the fact that researchers routinely download and examine untrusted code.

The variant I observed used malicious `.vbproj` files with MSBuild PreBuildEvents that execute automatically when projects load in Visual Studio.

**The kill chain:**

1. Researcher downloads the "PoC"

2. Opens the Visual Studio project

3. MSBuild executes the PreBuildEvent automatically

4. VBS script drops and runs AES-encrypted PowerShell

**What to inspect in source:**

- Project files (`*.csproj`, `*.vbproj`, `.sln`) for hidden build steps

- Build scripts with encoded download URLs or payload staging logic

- Auto-execution mechanisms triggered by IDE operations

**Safe workflow:**

- Open project files as text first; neutralize auto steps before building

- Use disposable VMs; snapshot before opening solutions

This technique has multiple variants ([documented example](https://checkmarx.com/blog/new-technique-to-trick-developers-detected-in-an-open-source-supply-chain-attack/)), demonstrating the importance of source review even for security tools and research materials.