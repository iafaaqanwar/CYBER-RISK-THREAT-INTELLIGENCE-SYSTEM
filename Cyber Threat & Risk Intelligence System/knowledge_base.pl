%% ============================================================
%%  knowledge_base.pl — Prolog Knowledge Base
%%  Cyber Risk & Threat Intelligence System
%% ============================================================
%%  First-Order Logic rules for:
%%    - Threat type classification
%%    - Risk level assignment
%%    - Mitigation strategy generation
%%    - Master diagnosis inference
%% ============================================================

%% ------------------------------------------------------------
%%  THREAT TYPE CLASSIFICATION RULES
%%  threat_type(Protocol, DstPort, PayloadIndicator, ThreatName)
%%
%%  Maps observed packet features to known attack categories.
%%  Protocol:          tcp | udp | icmp | http | dns | any
%%  DstPort:           Destination port number (integer)
%%  PayloadIndicator:  Keyword extracted from payload analysis
%%  ThreatName:        The diagnosed attack category (atom)
%% ------------------------------------------------------------

% --- DDoS / Flooding Attacks ---
threat_type(tcp, 80, syn_flood, ddos) :- !.
threat_type(tcp, 443, syn_flood, ddos) :- !.
threat_type(udp, _, udp_flood, ddos) :- !.
threat_type(icmp, _, ping_flood, ddos) :- !.
threat_type(tcp, 80, http_flood, ddos) :- !.
threat_type(tcp, 443, http_flood, ddos) :- !.

% --- Port Scanning ---
threat_type(tcp, _, syn_scan, port_scan) :- !.
threat_type(tcp, _, fin_scan, port_scan) :- !.
threat_type(tcp, _, xmas_scan, port_scan) :- !.
threat_type(tcp, _, null_scan, port_scan) :- !.
threat_type(udp, _, udp_scan, port_scan) :- !.

% --- SQL Injection ---
threat_type(tcp, 80, sql_pattern, sql_injection) :- !.
threat_type(tcp, 443, sql_pattern, sql_injection) :- !.
threat_type(tcp, 8080, sql_pattern, sql_injection) :- !.
threat_type(tcp, 3306, sql_pattern, sql_injection) :- !.

% --- Cross-Site Scripting (XSS) ---
threat_type(tcp, 80, xss_pattern, xss_attack) :- !.
threat_type(tcp, 443, xss_pattern, xss_attack) :- !.
threat_type(tcp, 8080, xss_pattern, xss_attack) :- !.

% --- Brute Force Attacks ---
threat_type(tcp, 22, repeated_auth, brute_force) :- !.
threat_type(tcp, 3389, repeated_auth, brute_force) :- !.
threat_type(tcp, 21, repeated_auth, brute_force) :- !.
threat_type(tcp, 23, repeated_auth, brute_force) :- !.
threat_type(tcp, 25, repeated_auth, brute_force) :- !.

% --- DNS Tunneling ---
threat_type(udp, 53, large_dns_query, dns_tunneling) :- !.
threat_type(tcp, 53, large_dns_query, dns_tunneling) :- !.
threat_type(udp, 53, encoded_subdomain, dns_tunneling) :- !.

% --- Man-in-the-Middle (MITM) ---
threat_type(tcp, _, arp_spoof, mitm_attack) :- !.
threat_type(tcp, 443, ssl_strip, mitm_attack) :- !.
threat_type(tcp, 80, ssl_strip, mitm_attack) :- !.

% --- Command & Control (C2) Beaconing ---
threat_type(tcp, 4444, reverse_shell, c2_beacon) :- !.
threat_type(tcp, 5555, reverse_shell, c2_beacon) :- !.
threat_type(tcp, 8443, periodic_beacon, c2_beacon) :- !.
threat_type(tcp, _, encoded_payload, c2_beacon) :- !.

% --- Data Exfiltration ---
threat_type(tcp, 443, large_outbound, data_exfiltration) :- !.
threat_type(tcp, 80, large_outbound, data_exfiltration) :- !.
threat_type(udp, 53, dns_exfil, data_exfiltration) :- !.

% --- Malware Communication ---
threat_type(tcp, _, known_malware_sig, malware_comm) :- !.
threat_type(udp, _, known_malware_sig, malware_comm) :- !.

% --- Default: Unknown / Anomalous Traffic ---
threat_type(_, _, _, unknown_threat).


%% ------------------------------------------------------------
%%  RISK LEVEL ASSIGNMENT
%%  risk_level(ThreatName, RiskRating)
%%
%%  Assigns a severity rating to each threat category.
%%  RiskRating: critical | high | medium | low
%% ------------------------------------------------------------

risk_level(ddos, critical).
risk_level(sql_injection, critical).
risk_level(c2_beacon, critical).
risk_level(data_exfiltration, critical).
risk_level(mitm_attack, critical).

risk_level(brute_force, high).
risk_level(xss_attack, high).
risk_level(malware_comm, high).
risk_level(dns_tunneling, high).

risk_level(port_scan, medium).

risk_level(unknown_threat, low).


%% ------------------------------------------------------------
%%  MITIGATION STRATEGIES
%%  mitigation(ThreatName, MitigationAction)
%%
%%  Recommends specific countermeasures for each threat type.
%% ------------------------------------------------------------

mitigation(ddos,
    'Deploy rate limiting and SYN cookies. Enable DDoS protection via WAF/CDN. Configure connection-rate thresholds on edge firewalls. Alert SOC team immediately.').

mitigation(port_scan,
    'Block source IP at perimeter firewall. Enable port scan detection on IDS/IPS. Review exposed services and close unnecessary ports. Implement network segmentation.').

mitigation(sql_injection,
    'Deploy WAF with SQL injection ruleset. Sanitize all user inputs with parameterized queries. Audit application code for injection vectors. Enable database activity monitoring.').

mitigation(xss_attack,
    'Implement Content Security Policy (CSP) headers. Sanitize and encode all user-generated output. Deploy WAF with XSS detection rules. Conduct application security review.').

mitigation(brute_force,
    'Enforce account lockout policies after 5 failed attempts. Implement MFA on all remote access services. Deploy fail2ban or equivalent. Monitor authentication logs for anomalies.').

mitigation(dns_tunneling,
    'Monitor DNS query lengths and entropy. Block known DNS tunneling tools at DNS resolver. Implement DNS filtering and DNSSEC. Restrict outbound DNS to authorized resolvers only.').

mitigation(mitm_attack,
    'Enforce HTTPS/HSTS across all services. Deploy certificate pinning. Enable Dynamic ARP Inspection (DAI) on switches. Segment network to limit lateral movement.').

mitigation(c2_beacon,
    'CRITICAL: Isolate affected host immediately. Block C2 IP/domain at firewall and DNS. Conduct forensic analysis on compromised system. Activate incident response procedure.').

mitigation(data_exfiltration,
    'CRITICAL: Block outbound traffic from affected host. Enable DLP policies on egress points. Investigate data access logs. Preserve forensic evidence and notify compliance team.').

mitigation(malware_comm,
    'Quarantine affected endpoint. Update antivirus signatures and run full scan. Block malware C2 domains/IPs. Review lateral movement indicators across the network.').

mitigation(unknown_threat,
    'Flag for manual SOC review. Capture full packet data for analysis. Correlate with threat intelligence feeds. Monitor source IP for further suspicious activity.').


%% ------------------------------------------------------------
%%  SUSPICIOUS TRAFFIC DETECTION
%%  is_suspicious(PacketCount, TimeWindowSeconds)
%%
%%  Determines if traffic volume exceeds normal thresholds.
%%  Returns true if packet rate exceeds 100 packets/second.
%% ------------------------------------------------------------

is_suspicious(PacketCount, TimeWindow) :-
    TimeWindow > 0,
    Rate is PacketCount / TimeWindow,
    Rate > 100.


%% ------------------------------------------------------------
%%  MASTER DIAGNOSIS RULE
%%  diagnose(Protocol, DstPort, PayloadIndicator, Result)
%%
%%  Unified inference rule that:
%%    1. Identifies the threat type from packet features
%%    2. Looks up the risk level
%%    3. Generates mitigation recommendations
%%    4. Returns a structured result
%%
%%  Result is unified with a compound term:
%%    diagnosis(ThreatName, RiskRating, MitigationAction)
%% ------------------------------------------------------------

diagnose(Protocol, DstPort, PayloadIndicator,
         diagnosis(ThreatName, RiskRating, MitigationAction)) :-
    threat_type(Protocol, DstPort, PayloadIndicator, ThreatName),
    risk_level(ThreatName, RiskRating),
    mitigation(ThreatName, MitigationAction).


%% ------------------------------------------------------------
%%  HELPER: Get all diagnostics for a protocol/port combo
%%  Used for batch processing multiple payload indicators.
%% ------------------------------------------------------------

diagnose_all(Protocol, DstPort, PayloadIndicators, Results) :-
    findall(
        diagnosis(ThreatName, RiskRating, MitigationAction),
        (
            member(Indicator, PayloadIndicators),
            threat_type(Protocol, DstPort, Indicator, ThreatName),
            risk_level(ThreatName, RiskRating),
            mitigation(ThreatName, MitigationAction)
        ),
        Results
    ).
