# Windows Investigation Cheatsheet

This cheatsheet is designed to help experienced red teamers conduct thorough investigations on Windows systems. It covers everything from system enumeration and user management to security and persistence techniques.

## 1. **System Information**

### General System Info:
- `systeminfo` - Provides detailed system configuration, including OS version, build, and memory
- `hostname` - Displays the computer's hostname
- `wmic os get caption, version, buildnumber, osarchitecture` - Get OS details (version, architecture)
- `ver` - Displays Windows version and build
- `tasklist` - Lists all running processes
- `msinfo32` - Opens the System Information tool (GUI-based)

### Network Info:
- `ipconfig /all` - Displays detailed network configuration (IP addresses, MAC addresses)
- `netstat -an` - Shows all active connections and listening ports
- `route print` - Displays the IP routing table
- `arp -a` - Displays the ARP table
- `nslookup <domain>` - Resolves DNS names to IP addresses
- `tracert <host>` - Traces the route to a destination
- `netsh interface ip show config` - Displays detailed network interface information

## 2. **User and Group Enumeration**

### User Account Info:
- `net user` - Lists all user accounts on the system
- `net user <username>` - Displays detailed information about a specific user account
- `whoami` - Displays the current logged-in user
- `echo %username%` - Displays the current user’s username (environment variable)
- `whoami /groups` - Shows the user’s group memberships
- `wmic useraccount get name,sid` - Get the list of all user accounts with their SID

### Group Info:
- `net localgroup` - Displays all local groups
- `net localgroup <groupname>` - Shows members of a specific local group
- `net group` - Displays global groups (for domain environments)
- `dsquery group` - Search Active Directory groups (requires RSAT)
- `net accounts` - Displays password policies and lockout settings

### Logins and Sessions:
- `query user` - Displays the currently logged-in users
- `logoff <session_id>` - Logs off a user by session ID
- `qwinsta` - Lists all RDP sessions (Terminal Services)
- `last` - Displays the last logon and logoff times of users (requires Unix-like tools installed)
  
## 3. **Security and Event Log Analysis**

### Security Logs:
- `eventvwr.msc` - Opens the Event Viewer (GUI)
- `wevtutil qe Security /f:text` - Query the security event logs (filtering optional)
- `wevtutil gl Security` - Get a list of event log channels
- `Get-WinEvent -LogName Security` - PowerShell command to fetch Security log events
- `auditpol /get /category:*` - Displays current audit policy settings
- `logon /logoff` - Event IDs 4624 (successful logon), 4634 (logoff), 4720 (user creation), 4726 (user deletion)

### Common Event IDs to Investigate:
- **4624**: Successful logon
- **4625**: Failed logon attempt
- **4634**: Logoff event
- **4648**: Logon using explicit credentials
- **4688**: New process created (important for detecting lateral movement)
- **4672**: Special privileges assigned to a new logon (admin group activity)

### PowerShell Event Logs:
- `Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational` - PowerShell command logs
- `Get-WinEvent -LogName Security | Where-Object { $_.Id -eq 4688 }` - Detect execution of commands (e.g., cmd.exe, PowerShell)

## 4. **File System & Persistence**

### File System Info:
- `dir /s /b C:\` - Lists all files recursively from the root of C:\
- `fsutil` - File system utilities (view file system properties, manage reparse points)
- `attrib` - Displays or changes file attributes
- `dir /ah` - Displays hidden files/folders
- `cacls <file>` - View file permissions
- `icacls <file>` - View or modify file permissions (more advanced than `cacls`)
- `handle.exe` (from Sysinternals) - View open file handles and locks

### Persistence Mechanisms:
- `reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run` - Displays autorun registry keys for current user
- `reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run` - Displays system-wide autorun registry keys
- `schtasks /query` - Lists all scheduled tasks
- `schtasks /create /tn <name> /tr <command> /sc onstart` - Create a new scheduled task (persistent method)
- `at` - Lists or creates scheduled tasks (older method)
- `tasklist /SVC` - Displays services running under each process (useful for persistence)

## 5. **Active Directory Enumeration (Domain Investigation)**

### Domain User and Group Enumeration:
- `net group /domain` - List all domain groups
- `net user /domain` - List all domain users
- `dsquery user -limit 0` - Enumerate all domain users (RSAT required)
- `dsquery group -limit 0` - Enumerate all domain groups
- `Get-ADUser -Filter *` - PowerShell command to enumerate domain users (requires RSAT)
- `Get-ADGroup -Filter *` - PowerShell command to enumerate domain groups (requires RSAT)

### Domain Admins and Privileged Groups:
- `net group "Domain Admins" /domain` - List Domain Admin group members
- `net group "Enterprise Admins" /domain` - List Enterprise Admin group members
- `net group "Schema Admins" /domain` - List Schema Admins group members
- `dsquery group -samid "Domain Admins"` - Find the SID of a domain admin group
- `Get-ADGroupMember "Domain Admins"` - List members of Domain Admins (requires RSAT)

### Group Policy & Local Admins:
- `gpresult /R` - Displays group policy results for the system
- `gpresult /H <file>.html` - Export group policy results to HTML
- `net localgroup administrators` - View local admin group members
- `secpol.msc` - Open Local Security Policy (GUI)
- `Get-WmiObject -Class Win32_GroupUser` - List group memberships for local users

## 6. **Privilege Escalation**

### Elevated Privileges:
- `whoami /groups` - List all group memberships, including SID
- `whoami /priv` - Show the user’s available privileges
- `net localgroup administrators` - View local admin group members
- `wmic useraccount where "name='Administrator'" get *` - Check if the Administrator account is enabled
- `net user administrator /active:yes` - Enable Administrator account if disabled

### Misconfigured Services & Sudo Equivalents:
- `sc qc <service_name>` - View configuration of a Windows service
- `sc config <service_name> binPath= <path>` - Modify service configuration (elevated privileges may be required)
- `Get-WmiObject -Class Win32_Service` - Enumerate services on a machine
- `net start <service_name>` - Start a service (useful for executing commands with elevated privileges)

## 7. **Lateral Movement & Remote Access**

### Remote Access Tools:
- `netstat -an | findstr :3389` - Check for open RDP (Remote Desktop Protocol) ports
- `mstsc` - Opens RDP client (Remote Desktop Connection)
- `powershell -Command "Start-Process mstsc"` - Open RDP via PowerShell
- `net use \\<ip>\ipc$` - Connect to a remote system (useful for file shares)
- `psexec` (Sysinternals) - Remote command execution with or without credentials
- `wmiexec.py` (Impacket) - Execute commands remotely via WMI (Windows Management Instrumentation)
  
### Lateral Movement via SMB:
- `net view \\<target-ip>` - View shared resources on a target machine
- `net use \\<target-ip>\<share>` - Connect to a remote share (if credentials are known)
- `smbclient //target-ip/share` - Interactive SMB client (requires Samba)
  
## 8. **Forensics and Evidence Collection**

### File Integrity Check:
- `sigcheck` (Sysinternals) - Verify file signatures (helpful to detect trojans or modified executables)
- `Get-FileHash <file_path>` - Generate file hash for comparison (e.g., MD5, SHA-1, SHA-256)
- `strings <file_path>` - Extract readable strings from binary files (useful for malware analysis)

### Memory Dump Collection:
- `tasklist /fi "imagename eq <process_name>"` - Find a specific process by name
- `procdump` (Sysinternals) - Dump the memory of a running process
- `dumpit` - Memory dump tool for live memory collection

### Timeline Creation:
- `Get-WinEvent -LogName Security | Export-Csv -Path C:\timeline.csv` - Export event logs to CSV for forensic analysis
- `Get-EventLog -LogName Security -After (Get-Date).AddDays(-7)` - Pull last 7 days of security logs

## 9. **Malware Analysis & Detection**

### Antivirus Bypass:
- `Get-MpPreference` - Displays Windows Defender settings
- `Get-MpThreat` - Lists all known threats by Windows Defender
- `Set-MpPreference -DisableRealtimeMonitoring $true` - Disable Windows Defender real-time protection (admin required)

### Malware Artifacts:
- `Get-WmiObject -Class Win32_Process` - List processes, check for suspicious activity
- `Get-WmiObject -Class Win32_StartupCommand` - Find programs configured to run at startup

---

This Windows Investigation Cheatsheet is designed to help you conduct in-depth and comprehensive investigations, identifying potential vulnerabilities, misconfigurations, and traces of malicious activity across Windows environments. By using this guide, you can gather critical data for forensic analysis, threat hunting, and system hardening.

