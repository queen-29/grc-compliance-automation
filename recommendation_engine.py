
"""
GRC Compliance Automation Platform
Recommendation Engine

Provides rule-based suggestions for:
- ISO 27001:2022 controls
- NIST SP 800-53 controls
- Remediation actions
- Audit evidence

All recommendations require human review.
"""

RULES = [
    {
        "name": "Unpatched software or vulnerabilities",
        "keywords": [
            "patch", "unpatched", "vulnerability", "outdated software",
            "outdated system", "security update", "known exploit"
        ],
        "iso": [
            {
                "control": "A.8.8",
                "name": "Management of technical vulnerabilities",
                "reason": "Addresses identification and management of technical vulnerabilities."
            },
            {
                "control": "A.8.9",
                "name": "Configuration management",
                "reason": "Supports secure and controlled system configurations."
            }
        ],
        "nist": [
            {
                "control": "SI-2",
                "name": "Flaw Remediation"
            },
            {
                "control": "RA-5",
                "name": "Vulnerability Monitoring and Scanning"
            }
        ],
        "remediation": [
            "Identify affected systems and assess vulnerability severity.",
            "Prioritize critical security patches based on exposure and business impact.",
            "Test patches in a controlled environment before deployment.",
            "Deploy approved patches and verify successful installation.",
            "Establish a recurring vulnerability scanning and patch review process."
        ],
        "evidence": [
            "Vulnerability scan reports.",
            "Patch management records.",
            "Change management approvals.",
            "Patch deployment logs.",
            "Post-remediation verification results."
        ]
    },
    {
        "name": "Multi-factor authentication weakness",
        "keywords": [
            "mfa", "multi-factor", "multifactor",
            "two-factor", "2fa", "authentication"
        ],
        "iso": [
            {
                "control": "A.5.15",
                "name": "Access control",
                "reason": "Addresses rules for controlling access to information and systems."
            },
            {
                "control": "A.5.17",
                "name": "Authentication information",
                "reason": "Addresses secure handling of authentication information."
            }
        ],
        "nist": [
            {
                "control": "IA-2",
                "name": "Identification and Authentication (Organizational Users)"
            },
            {
                "control": "IA-5",
                "name": "Authenticator Management"
            }
        ],
        "remediation": [
            "Identify systems and user accounts that do not enforce MFA.",
            "Enable MFA for privileged and remote access accounts.",
            "Extend MFA enforcement to other in-scope accounts.",
            "Document approved exceptions and compensating controls.",
            "Periodically review MFA enforcement and exceptions."
        ],
        "evidence": [
            "Identity provider MFA configuration screenshots.",
            "MFA enforcement policies.",
            "User enrollment reports.",
            "Privileged account access reports.",
            "Documented MFA exceptions and approvals."
        ]
    },
    {
        "name": "Excessive access privileges",
        "keywords": [
            "unauthorized access", "excessive access",
            "privileged access", "access rights",
            "permissions", "user access", "least privilege"
        ],
        "iso": [
            {
                "control": "A.5.15",
                "name": "Access control",
                "reason": "Supports defined access control rules."
            },
            {
                "control": "A.5.18",
                "name": "Access rights",
                "reason": "Addresses granting, reviewing and removing access rights."
            }
        ],
        "nist": [
            {
                "control": "AC-2",
                "name": "Account Management"
            },
            {
                "control": "AC-6",
                "name": "Least Privilege"
            }
        ],
        "remediation": [
            "Review user accounts and their assigned permissions.",
            "Remove unnecessary or excessive access privileges.",
            "Apply least-privilege access principles.",
            "Require approval for privileged access.",
            "Schedule periodic access reviews."
        ],
        "evidence": [
            "User access review reports.",
            "Access control policies.",
            "Privileged account listings.",
            "Access approval records.",
            "Records of removed or modified permissions."
        ]
    },
    {
        "name": "Backup and recovery weakness",
        "keywords": [
            "backup", "backups", "recovery",
            "disaster recovery", "data restoration",
            "restore testing"
        ],
        "iso": [
            {
                "control": "A.8.13",
                "name": "Information backup",
                "reason": "Addresses maintaining and testing information backups."
            },
            {
                "control": "A.5.30",
                "name": "ICT readiness for business continuity",
                "reason": "Addresses ICT readiness supporting business continuity."
            }
        ],
        "nist": [
            {
                "control": "CP-9",
                "name": "System Backup"
            },
            {
                "control": "CP-10",
                "name": "System Recovery and Reconstitution"
            }
        ],
        "remediation": [
            "Define backup frequency and retention requirements.",
            "Configure automated backups for critical systems and data.",
            "Protect backup copies against unauthorized access or alteration.",
            "Perform periodic restoration tests.",
            "Document backup failures and recovery test results."
        ],
        "evidence": [
            "Backup schedules and policies.",
            "Backup job execution logs.",
            "Backup access permissions.",
            "Restoration test reports.",
            "Recovery procedures."
        ]
    },
    {
        "name": "Insufficient security logging",
        "keywords": [
            "logging", "logs", "monitoring",
            "audit trail", "security events",
            "log retention", "event monitoring"
        ],
        "iso": [
            {
                "control": "A.8.15",
                "name": "Logging",
                "reason": "Addresses production, storage, protection and analysis of logs."
            },
            {
                "control": "A.8.16",
                "name": "Monitoring activities",
                "reason": "Addresses monitoring networks, systems and applications."
            }
        ],
        "nist": [
            {
                "control": "AU-2",
                "name": "Event Logging"
            },
            {
                "control": "AU-6",
                "name": "Audit Record Review, Analysis, and Reporting"
            }
        ],
        "remediation": [
            "Identify critical systems requiring security event logging.",
            "Enable appropriate logging on in-scope systems.",
            "Define log retention and protection requirements.",
            "Establish regular log review and alert handling procedures.",
            "Test monitoring coverage and document exceptions."
        ],
        "evidence": [
            "Logging configuration records.",
            "Centralized log monitoring screenshots.",
            "Log retention settings.",
            "Security alert records.",
            "Documented log review reports."
        ]
    }
]


def get_recommendations(title, description="", category=""):
    """
    Match a finding against known risk patterns
    and return suggested GRC recommendations.
    """

    text = " ".join([
        str(title or ""),
        str(description or ""),
        str(category or "")
    ]).lower()

    matched_rules = []

    for rule in RULES:
        if any(keyword in text for keyword in rule["keywords"]):
            matched_rules.append(rule)

    if not matched_rules:
        return {
            "matched": False,
            "finding_type": "General security or compliance finding",
            "iso_controls": [],
            "nist_controls": [],
            "remediation": [
                "Investigate and document the underlying issue.",
                "Identify affected systems, processes and information.",
                "Assess the business and security impact.",
                "Assign a responsible owner and target remediation date.",
                "Define corrective actions and verify their completion."
            ],
            "evidence": [
                "Documented finding and investigation results.",
                "Relevant policies and procedures.",
                "Risk assessment records.",
                "Corrective action records.",
                "Evidence demonstrating remediation."
            ],
            "review_required": True
        }

    iso_controls = []
    nist_controls = []
    remediation = []
    evidence = []

    for rule in matched_rules:
        for control in rule["iso"]:
            if control not in iso_controls:
                iso_controls.append(control)

        for control in rule["nist"]:
            if control not in nist_controls:
                nist_controls.append(control)

        for action in rule["remediation"]:
            if action not in remediation:
                remediation.append(action)

        for item in rule["evidence"]:
            if item not in evidence:
                evidence.append(item)

    return {
        "matched": True,
        "finding_type": ", ".join(
            rule["name"] for rule in matched_rules
        ),
        "iso_controls": iso_controls,
        "nist_controls": nist_controls,
        "remediation": remediation,
        "evidence": evidence,
        "review_required": True
    }
