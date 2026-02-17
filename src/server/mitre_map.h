#ifndef MITRE_MAP_H
#define MITRE_MAP_H

// =============================================================================
// SecureSeaHorse SIEM — Phase 4: MITRE ATT&CK Technique Mapping
// =============================================================================
// Maps each detection sub-type to its official MITRE ATT&CK technique ID,
// tactic, and description. Used by TrafficClassifier to tag detections.
//
// Reference: https://attack.mitre.org/techniques/enterprise/
// =============================================================================

#include <string>
#include <map>

struct MitreTechnique {
    std::string id;           // e.g. "T1498"
    std::string name;         // e.g. "Network Denial of Service"
    std::string tactic;       // e.g. "Impact"
    std::string url;          // Link to MITRE page
};

// =============================================================================
// GLOBAL MITRE REGISTRY — Populated at startup, read-only thereafter
// =============================================================================
inline const std::map<std::string, MitreTechnique>& get_mitre_map() {
    static const std::map<std::string, MitreTechnique> mitre = {

        // =====================================================================
        // DDoS — Impact
        // =====================================================================
        {"ddos_volumetric", {
            "T1498", "Network Denial of Service",
            "Impact",
            "https://attack.mitre.org/techniques/T1498/"
        }},
        {"ddos_syn_flood", {
            "T1498.001", "Network Denial of Service: Direct Network Flood",
            "Impact",
            "https://attack.mitre.org/techniques/T1498/001/"
        }},
        {"ddos_amplification", {
            "T1498.002", "Network Denial of Service: Reflection Amplification",
            "Impact",
            "https://attack.mitre.org/techniques/T1498/002/"
        }},
        {"ddos_application_layer", {
            "T1499", "Endpoint Denial of Service",
            "Impact",
            "https://attack.mitre.org/techniques/T1499/"
        }},

        // =====================================================================
        // Port Scanning — Reconnaissance / Discovery
        // =====================================================================
        {"portscan_sequential", {
            "T1046", "Network Service Scanning",
            "Discovery",
            "https://attack.mitre.org/techniques/T1046/"
        }},
        {"portscan_stealth", {
            "T1046", "Network Service Scanning",
            "Discovery",
            "https://attack.mitre.org/techniques/T1046/"
        }},
        {"portscan_service_enum", {
            "T1046", "Network Service Scanning",
            "Discovery",
            "https://attack.mitre.org/techniques/T1046/"
        }},
        {"portscan_os_fingerprint", {
            "T1592.004", "Gather Victim Host Information: Client Configurations",
            "Reconnaissance",
            "https://attack.mitre.org/techniques/T1592/004/"
        }},

        // =====================================================================
        // Brute Force — Credential Access
        // =====================================================================
        {"bruteforce_standard", {
            "T1110.001", "Brute Force: Password Guessing",
            "Credential Access",
            "https://attack.mitre.org/techniques/T1110/001/"
        }},
        {"bruteforce_credential_stuffing", {
            "T1110.004", "Brute Force: Credential Stuffing",
            "Credential Access",
            "https://attack.mitre.org/techniques/T1110/004/"
        }},
        {"bruteforce_password_spray", {
            "T1110.003", "Brute Force: Password Spraying",
            "Credential Access",
            "https://attack.mitre.org/techniques/T1110/003/"
        }},

        // =====================================================================
        // Data Exfiltration — Exfiltration
        // =====================================================================
        {"exfil_volume_anomaly", {
            "T1048", "Exfiltration Over Alternative Protocol",
            "Exfiltration",
            "https://attack.mitre.org/techniques/T1048/"
        }},
        {"exfil_dns_tunneling", {
            "T1048.001", "Exfiltration Over Alternative Protocol: Exfiltration Over Symmetric Encrypted Non-C2 Protocol",
            "Exfiltration",
            "https://attack.mitre.org/techniques/T1048/001/"
        }},
        {"exfil_large_transfer", {
            "T1030", "Data Transfer Size Limits",
            "Exfiltration",
            "https://attack.mitre.org/techniques/T1030/"
        }},
        {"exfil_unusual_dest", {
            "T1567", "Exfiltration Over Web Service",
            "Exfiltration",
            "https://attack.mitre.org/techniques/T1567/"
        }},

        // =====================================================================
        // C2 Beaconing — Command and Control
        // =====================================================================
        {"c2_periodic_beacon", {
            "T1071", "Application Layer Protocol",
            "Command and Control",
            "https://attack.mitre.org/techniques/T1071/"
        }},
        {"c2_dns_beacon", {
            "T1071.004", "Application Layer Protocol: DNS",
            "Command and Control",
            "https://attack.mitre.org/techniques/T1071/004/"
        }},
        {"c2_http_beacon", {
            "T1071.001", "Application Layer Protocol: Web Protocols",
            "Command and Control",
            "https://attack.mitre.org/techniques/T1071/001/"
        }},
        {"c2_known_framework", {
            "T1219", "Remote Access Software",
            "Command and Control",
            "https://attack.mitre.org/techniques/T1219/"
        }},
        {"c2_encrypted_channel", {
            "T1573", "Encrypted Channel",
            "Command and Control",
            "https://attack.mitre.org/techniques/T1573/"
        }},

        // =====================================================================
        // Lateral Movement — Lateral Movement / Discovery
        // =====================================================================
        {"lateral_internal_scan", {
            "T1018", "Remote System Discovery",
            "Discovery",
            "https://attack.mitre.org/techniques/T1018/"
        }},
        {"lateral_pass_the_hash", {
            "T1550.002", "Use Alternate Authentication Material: Pass the Hash",
            "Lateral Movement",
            "https://attack.mitre.org/techniques/T1550/002/"
        }},
        {"lateral_pass_the_ticket", {
            "T1550.003", "Use Alternate Authentication Material: Pass the Ticket",
            "Lateral Movement",
            "https://attack.mitre.org/techniques/T1550/003/"
        }},
        {"lateral_rdp", {
            "T1021.001", "Remote Services: Remote Desktop Protocol",
            "Lateral Movement",
            "https://attack.mitre.org/techniques/T1021/001/"
        }},
        {"lateral_smb", {
            "T1021.002", "Remote Services: SMB/Windows Admin Shares",
            "Lateral Movement",
            "https://attack.mitre.org/techniques/T1021/002/"
        }},
        {"lateral_ssh", {
            "T1021.004", "Remote Services: SSH",
            "Lateral Movement",
            "https://attack.mitre.org/techniques/T1021/004/"
        }},
        {"lateral_wmi", {
            "T1047", "Windows Management Instrumentation",
            "Execution",
            "https://attack.mitre.org/techniques/T1047/"
        }},
    };

    return mitre;
}

// =============================================================================
// LOOKUP HELPER — Returns a default "Unknown" technique if key not found
// =============================================================================
inline MitreTechnique lookup_mitre(const std::string& sub_type) {
    const auto& map = get_mitre_map();
    auto it = map.find(sub_type);
    if (it != map.end()) {
        return it->second;
    }
    return {"N/A", "Unknown Technique", "Unknown", ""};
}

#endif
