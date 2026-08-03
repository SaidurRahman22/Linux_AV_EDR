<!-- Source: Google Doc https://docs.google.com/document/d/1NTG_e6gfl1sLnYocr0BRGJJc2OM4Ii12jPMR8SckcCo/edit
     Imported verbatim on 2026-08-03. Do not treat as final design;
     this is the reference SRS we will discuss. -->

Software Requirements Specification (SRS): Linux AV & Wazuh Integrator
Version: 2.0 (Updated Specification)
Target Audience: Senior Software Engineers, Cybersecurity Architects, and AI Coding Agents.
1. Project Overview
The proposed system is an enterprise-grade Linux Antivirus and Endpoint Detection and Response (EDR) solution. It integrates natively with Wazuh, providing real-time threat detection (signature and behavioral), Host Intrusion Prevention System (HIPS) capabilities, dynamic Wazuh rule generation, and centralized threat intelligence. The ecosystem consists of a distributed Linux endpoint agent, an automated Threat Intelligence Crawler Beacon, and a centralized admin web dashboard for fleet monitoring, granular whitelisting, MITRE ATT&CK log correlation, and remote quarantine management.
2. System Architecture & Component Mind Map
2.1 High-Level Architecture Visual Mapping
The diagram below illustrates the complete bi-directional data flow between the Central Web Dashboard, the automated Threat Intel Crawler Beacon, distributed Linux Endpoints, and local/remote Wazuh instances:




Central Web Dashboard (Admin UI, REST API & Power Query Search)


▲ Incoming Telemetry
Status, Clean Logs, MITRE TTPs, Blocked IPs
▼ Outgoing Commands
IOC Push, Whitelist Policies, Admin Cmds


LINUX ENDPOINT GROUP (INSTANCES)


Linux AV Agent
(Scanner, eBPF HIPS Engine, Firewall, Quarantine)
Wazuh Agent
(Local OSSEC Log Ingestion & Rule Reload)


Threat Intel Scraper Beacon
(OSINT Crawler: IPs, Hashes, Signatures)
Wazuh Server
(Remote SIEM & Central Ruleset Storage)
2.2 Low-Level Component Mind Map & Interaction
* Linux AV Agent Daemon (Endpoint Instance):
   * Signature & Hash Scanner: Scans files against local YARA rules and cryptographic hash databases (MD5/SHA256) on-access and on-demand.
   * Behavioral Analysis Engine: Utilizes eBPF kernel hooks or auditd tracing to intercept execve, process forks, and unauthorized memory access.
   * Host IPS Module: Integrates directly with nftables/iptables APIs to instantly drop inbound/outbound connection attempts from malicious IPs and report block events to the central server.
   * Quarantine Manager: Encrypts and moves suspicious/malicious binaries to /opt/av/quarantine, revoking all execution permissions.
   * Wazuh Integrator & Dynamic Rule Engine: Emits clean JSON logs to local Wazuh agent decoders and dynamically compiles standard Wazuh XML rules upon novel threat detections.
   * Local Policy Evaluator: Applies global and device-specific allow-lists to bypass whitelisted binaries or IP addresses before taking isolation actions.
* Central Management Server & Web Dashboard:
   * Fleet & Instance Manager: Provides real-time status, agent health, uptime, and OS version tracking across all installed Linux endpoints.
   * Global IOC & Rule Center: Aggregates and displays all antivirus rules, malicious file hashes, blocked IPs, and detected threats reported across the fleet.
   * Targeted Allow-List Controller: Scope selection dropdown (Global vs. Specific Device Name) for IP address whitelisting and process/program path overrides.
   * Log Analytics & Query Engine: High-performance log viewer featuring a powerful search bar supporting free text and field-based queries, ISO 8601 UTC timestamps, and explicit MITRE ATT&CK framework mapping.
   * Automated Threat Intel Scraper Beacon: Automated web crawler scraping open-source threat intelligence feeds (AbuseIPDB, ThreatFox, AlienVault OTX, URLhaus) to dynamically populate IOC databases.
3. Detailed Functional Requirements
3.1 Web Dashboard & Threat Inventory
Feature Module
	Requirement Specification
	Technical Detail
	Global Rules & IOC Inventory
	Central view listing all active antivirus rules, malware file hashes (MD5/SHA256), malicious domain URLs, and blocked IP addresses detected across instances or pushed by admins.
	PostgreSQL relational storage synced via WebSocket/gRPC channels to all endpoint agents.
	Blocked IP Visibility Page
	Web UI aggregating all IPs actively blocked by endpoint Host IPS modules, displaying the host device name, trigger count, and initial block timestamp.
	Endpoints push dynamic nftables block events in real time to the central ingestion API.
	3.2 Allow-List & Whitelisting Framework
Feature Module
	Requirement Specification
	Technical Detail
	Target Scope Selector
	Dropdown interface in dashboard enabling admins to apply allow-list rules either Globally (all installed instances) or targeted to a Specific Device / Instance Name.
	Policy payload contains scope: "GLOBAL" | "INSTANCE_UUID" to ensure local agents filter rules appropriately.
	IP Address Whitelist
	Admin ability to specify IP addresses or CIDR blocks exempted from Host IPS blocking and network dropping.
	Endpoints maintain a high-priority nftables bypass chain evaluated before threat blocking chains.
	Process & Binary Allow-List
	Admin ability to white-list specific binaries, full executable file paths, parent process IDs, or cryptographic file hashes to allow execution without triggering AV isolation.
	Kernel eBPF hooks cross-reference file hashes and paths against local memory-mapped allow-list tables prior to taking quarantine action.
	3.3 Log Analytics, Power Query Search & MITRE ATT&CK Mapping
Feature Module
	Requirement Specification
	Technical Detail
	Power Query Search Box
	Log Viewer equipped with an advanced search bar supporting both free-text searches and field-based query expressions (e.g., ip:192.168.1.50 AND mitre_id:T1059, severity:HIGH).
	Backed by Elasticsearch / OpenSearch or PostgreSQL Full-Text Search with Lucene-like query parsing.
	Clean & Detailed Format
	Logs rendered cleanly with expandable JSON details, standardized ISO 8601 UTC timestamps (YYYY-MM-DDTHH:mm:ss.sssZ), origin host name, and clear action results (e.g., BLOCKED, QUARANTINED, WHITELISTED).
	Log format normalized into standard JSON schema across agent, dashboard, and Wazuh log decoders.
	MITRE ATT&CK Framework Mapping
	Every logged event and alert is explicitly enriched with corresponding MITRE ATT&CK Tactics (e.g., Execution, Persistence) and Technique IDs (e.g., T1059.004, T1543).
	Detection engine correlates behavioral triggers with built-in MITRE ATT&CK taxonomy dictionary before log dispatch.
	4. Automated Threat Intelligence Web Scraper Beacon
To ensure real-time proactive protection, the system incorporates an automated online Threat Intelligence Beacon Crawler Microservice.
* Feed Crawling & Scraping Engine: Continuously polls and crawls open-source threat intelligence (OSINT) repositories, C2 trackers, security advisories, and malicious payload feeds (e.g., AbuseIPDB, ThreatFox, Abuse.ch URLhaus, AlienVault OTX, VirusTotal API, MISP).
* Automated Parsing & Normalization: Extracted data is automatically parsed, sanitized, and classified into standardized IOC categories:
   * IP IOCs: Malicious C2 IPs, botnet exit nodes, scanner IPs.
   * File Hash IOCs: SHA-256, SHA-1, and MD5 hashes of known malware strains.
   * YARA / Signatures: Dynamic rules and pattern strings for emerging Linux exploits.
   * Domain / URL IOCs: Malicious phishing and malware distribution domains.
* Automated Fleet Sync: Newly harvested high-confidence IOCs are automatically categorized in the Web Dashboard and immediately broadcasted to all active Linux Antivirus endpoint instances via gRPC/WebSocket channels for instant local blocking.
5. Log Schema Specification (JSON)
Below is the standardized JSON event log structure produced by the endpoint agent and parsed by the web search engine and Wazuh decoders:
{
 "timestamp": "2026-08-03T13:23:32.000Z",
 "instance": {
   "device_name": "prod-srv-db-01",
   "uuid": "a3b1c2d3-e4f5-6789-0123-456789abcdef",
   "ip_address": "10.0.4.15"
 },
 "event": {
   "type": "HIPS_NETWORK_BLOCK",
   "action_taken": "BLOCKED",
   "severity": "HIGH",
   "details": {
     "source_ip": "198.51.100.42",
     "destination_port": 443,
     "process_path": "/usr/bin/curl",
     "process_id": 4821
   }
 },
 "mitre_attack": {
   "tactic": "Command and Control",
   "tactic_id": "TA0011",
   "technique": "Application Layer Protocol",
   "technique_id": "T1071.001"
 },
 "policy": {
   "allowlisted": false,
   "matching_ioc_type": "MALICIOUS_IP"
 }
}

6. System Interaction Flows (Use Cases)
1. Automated Threat Intelligence Ingestion & Blocking:
   * Threat Intel Beacon crawls OSINT source and identifies a new malicious C2 IP.
   * Beacon parses IP, enriches with MITRE ATT&CK ID T1071.001 (Application Layer Protocol), and inserts into Central IOC DB.
   * Dashboard broadcasts the updated IP list to all connected endpoint instances.
   * Endpoint AV Agent updates local nftables rule. Future connection attempts to this IP are blocked in milliseconds and logged.
2. Admin Granular Whitelisting Override:
   * Admin observes a false-positive process block on custom internal binary /opt/internal_app/sync.sh on endpoint dev-node-01.
   * Admin navigates to Whitelist Manager on Dashboard, selects dev-node-01 from the instance dropdown, and inputs executable path and SHA-256 hash.
   * Dashboard transmits updated allow-list policy specifically to dev-node-01.
   * Endpoint agent adds hash/path to local bypass memory, allowing uninterrupted execution while maintaining global blocking on other instances.
3. Power Query Search Investigation:
   * Security Analyst accesses the Log View page.
   * Analyst executes query: device_name: "prod-srv-db-01" AND mitre_attack.technique_id: "T1059.004".
   * Engine instantly filters logs, rendering clean timeline entries with exact UTC timestamps, execution parameters, and quarantine actions.
7. Technical Stack & Implementation Architecture
* Endpoint Agent Daemon: Go (Golang) or Rust for low memory footprint, strict memory safety, native eBPF binding (cilium/ebpf), and direct nftables interaction.
* Threat Intel Scraper Beacon: Python (Asyncio / Playwright / Scrapy) or Node.js background worker integrated with STIX/TAXII parsers.
* Central Web Dashboard Backend: Node.js (TypeScript/Express) or Python (FastAPI) with gRPC/WebSocket for agent communication.
* Database & Search Index: PostgreSQL (relational state and policy management) paired with OpenSearch / Elasticsearch for high-speed log search and query parsing.