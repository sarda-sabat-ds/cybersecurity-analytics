"""
Synthetic cybersecurity log dataset generator.

Generates large, realistic security event logs for ML training and demo purposes.
Labels are assigned deterministically based on event characteristics.

LIMITATION: This is synthetic data generated with rule-based labels — not real
threat intelligence. Model performance on real-world logs will differ.
"""
import logging
import random
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

RANDOM_SEED = 42
random.seed(RANDOM_SEED)
np.random.seed(RANDOM_SEED)

# ---------------------------------------------------------------------------
# Expanded constants for a large, varied dataset
# ---------------------------------------------------------------------------
EVENT_TYPES = [
    "login_success", "login_failure", "file_access", "file_write",
    "file_delete", "network_connection", "dns_query", "http_request",
    "port_scan", "privilege_escalation", "data_exfiltration",
    "brute_force", "malware_detected", "configuration_change",
    "user_creation", "user_deletion", "account_lockout",
    "firewall_block", "vpn_connect", "vpn_disconnect",
    "process_creation", "registry_modification", "scheduled_task",
    "lateral_movement", "credential_dumping", "ransomware_activity",
    "c2_communication", "sql_injection", "xss_attempt",
]

NORMAL_EVENT_TYPES = [
    "login_success", "file_access", "network_connection", "dns_query",
    "http_request", "configuration_change", "vpn_connect", "vpn_disconnect",
    "process_creation", "scheduled_task", "file_write",
]

SUSPICIOUS_EVENT_TYPES = [
    "port_scan", "brute_force", "data_exfiltration", "privilege_escalation",
    "malware_detected", "account_lockout", "lateral_movement",
    "credential_dumping", "ransomware_activity", "c2_communication",
    "sql_injection", "xss_attempt", "registry_modification",
]

SEVERITY_BY_EVENT = {
    "login_success":        "low",
    "login_failure":        "medium",
    "file_access":          "low",
    "file_write":           "low",
    "file_delete":          "medium",
    "network_connection":   "low",
    "dns_query":            "low",
    "http_request":         "low",
    "port_scan":            "medium",
    "privilege_escalation": "high",
    "data_exfiltration":    "critical",
    "brute_force":          "high",
    "malware_detected":     "critical",
    "configuration_change": "low",
    "user_creation":        "medium",
    "user_deletion":        "medium",
    "account_lockout":      "high",
    "firewall_block":       "medium",
    "vpn_connect":          "low",
    "vpn_disconnect":       "low",
    "process_creation":     "low",
    "registry_modification":"high",
    "scheduled_task":       "medium",
    "lateral_movement":     "critical",
    "credential_dumping":   "critical",
    "ransomware_activity":  "critical",
    "c2_communication":     "critical",
    "sql_injection":        "high",
    "xss_attempt":          "medium",
}

# Large diverse IP pools
INTERNAL_SUBNETS = (
    [f"192.168.{i}.{j}" for i in range(1, 11) for j in range(1, 50)] +
    [f"10.10.{i}.{j}"   for i in range(0, 5)  for j in range(1, 30)] +
    [f"172.16.{i}.{j}"  for i in range(0, 4)  for j in range(1, 20)]
)
EXTERNAL_IPS = (
    ["203.0.113.5", "198.51.100.10", "185.220.101.12", "91.108.4.32",
     "176.10.99.200", "45.33.32.156", "80.82.77.33", "94.102.49.190",
     "194.165.16.11", "62.233.50.246", "89.234.157.254", "198.199.88.43",
     "104.21.14.80",  "172.67.68.228", "104.26.3.14",   "162.142.125.0",
     "167.248.133.0", "205.185.216.0", "93.174.95.106",  "77.83.142.33"] +
    [f"5.{a}.{b}.{c}" for a,b,c in [(188,0,10),(188,0,11),(255,70,1),(255,70,2)]] +
    [f"45.{a}.{b}.{c}" for a,b,c in [(141,215,10),(141,215,11),(227,22,50)]]
)
ASSETS = [
    "web-server-01", "web-server-02", "web-server-03",
    "db-server-01",  "db-server-02",  "db-server-03",
    "auth-server-01","auth-server-02",
    "file-server-01","file-server-02",
    "mail-server-01","mail-server-02",
    "workstation-A", "workstation-B", "workstation-C", "workstation-D",
    "workstation-E", "workstation-F", "workstation-G", "workstation-H",
    "firewall-01",   "firewall-02",
    "vpn-gateway",   "load-balancer-01",
    "backup-server-01","jump-host-01",
    "monitoring-01", "proxy-server-01",
    "dev-server-01", "staging-server-01",
]
USERS = [
    "alice.smith", "bob.jones", "carol.white", "dave.brown", "eve.taylor",
    "frank.davis", "grace.wilson", "henry.moore", "iris.jackson", "jack.martin",
    "karen.lee",   "liam.harris", "mona.clark",  "nate.lewis",   "olivia.hall",
    "paul.young",  "quinn.allen", "rose.king",   "sam.wright",   "tina.scott",
    "admin",       "root",        "service_acct","backup_user",  "api_user",
    "dev01",       "dev02",       "ops01",       "svc_db",       "svc_web",
]
COMMON_PORTS = [20,21,22,23,25,53,80,110,143,389,443,445,
                636,993,995,1433,1521,3306,3389,4444,5432,
                5900,6379,8080,8443,8888,9200,27017,50000]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "curl/7.68.0", "python-requests/2.28.0",
    "Nmap Scripting Engine", "sqlmap/1.6", "Nikto/2.1.6",
    "Go-http-client/1.1", "Wget/1.21",
]
PROCESSES = [
    "chrome.exe","svchost.exe","explorer.exe","cmd.exe","powershell.exe",
    "python.exe","node.exe","java.exe","mimikatz.exe","psexec.exe",
    "meterpreter","nc.exe","nmap","hydra","metasploit",
]


def _rip(external: bool = False) -> str:
    return random.choice(EXTERNAL_IPS if external else INTERNAL_SUBNETS)

def _rts(start: datetime, end: datetime) -> datetime:
    return start + timedelta(seconds=random.randint(0, int((end - start).total_seconds())))

def _base(event_type: str, ts: datetime, src_ip: str = None, dst_ip: str = None,
          asset: str = None) -> dict:
    sev = SEVERITY_BY_EVENT.get(event_type, "low")
    return {
        "log_id":             str(uuid.uuid4()),
        "timestamp":          ts.isoformat(),
        "source_ip":          src_ip or _rip(external=False),
        "destination_ip":     dst_ip or _rip(external=False),
        "event_type":         event_type,
        "severity":           sev,
        "failed_login_count": 0,
        "request_count":      1,
        "port":               random.choice(COMMON_PORTS),
        "affected_asset":     asset or random.choice(ASSETS),
        "username":           random.choice(USERS),
        "user_agent":         None,
        "process_name":       None,
        "bytes_transferred":  0,
        "label":              "normal",
    }

# ---------------------------------------------------------------------------
# Normal record generators
# ---------------------------------------------------------------------------

def _gen_login_success(ts: datetime) -> dict:
    r = _base("login_success", ts)
    r["port"] = random.choice([22, 443, 389, 3389])
    return r

def _gen_file_access(ts: datetime) -> dict:
    r = _base("file_access", ts)
    r["request_count"] = random.randint(1, 30)
    r["bytes_transferred"] = random.randint(512, 50_000)
    return r

def _gen_http_request(ts: datetime) -> dict:
    r = _base("http_request", ts, dst_ip=_rip(external=True))
    r["port"] = random.choice([80, 443, 8080, 8443])
    r["request_count"] = random.randint(1, 20)
    r["user_agent"] = random.choice(USER_AGENTS[:4])
    r["bytes_transferred"] = random.randint(1_000, 200_000)
    return r

def _gen_dns_query(ts: datetime) -> dict:
    r = _base("dns_query", ts)
    r["port"] = 53
    r["request_count"] = random.randint(1, 10)
    return r

def _gen_vpn(ts: datetime) -> dict:
    et = random.choice(["vpn_connect", "vpn_disconnect"])
    r = _base(et, ts, src_ip=_rip(external=True))
    r["port"] = random.choice([443, 1194, 500])
    return r

def _gen_config_change(ts: datetime) -> dict:
    r = _base("configuration_change", ts)
    return r

def _gen_process_creation(ts: datetime) -> dict:
    r = _base("process_creation", ts)
    r["process_name"] = random.choice(PROCESSES[:5])
    return r

# ---------------------------------------------------------------------------
# Suspicious record generators
# ---------------------------------------------------------------------------

def _gen_brute_force(ts: datetime, src_ip: str = None) -> dict:
    ip = src_ip or _rip(external=True)
    failed = random.randint(8, 80)
    r = _base("brute_force", ts, src_ip=ip,
              asset=random.choice(["auth-server-01","auth-server-02","web-server-01","vpn-gateway"]))
    r["severity"] = "critical" if failed > 40 else "high"
    r["failed_login_count"] = failed
    r["request_count"] = failed
    r["port"] = random.choice([22, 3389, 21, 389, 443])
    r["label"] = "suspicious"
    return r

def _gen_port_scan(ts: datetime, src_ip: str = None) -> dict:
    ip = src_ip or _rip(external=True)
    r = _base("port_scan", ts, src_ip=ip)
    r["request_count"] = random.randint(100, 2000)
    r["port"] = random.choice(COMMON_PORTS)
    r["user_agent"] = "Nmap Scripting Engine"
    r["label"] = "suspicious"
    return r

def _gen_data_exfiltration(ts: datetime) -> dict:
    r = _base("data_exfiltration", ts,
              src_ip=_rip(external=False),
              dst_ip=_rip(external=True),
              asset=random.choice(["db-server-01","db-server-02","file-server-01","backup-server-01"]))
    r["request_count"] = random.randint(500, 10_000)
    r["bytes_transferred"] = random.randint(500_000, 50_000_000)
    r["port"] = random.choice([443, 80, 8443, 21, 22])
    r["label"] = "suspicious"
    return r

def _gen_priv_esc(ts: datetime) -> dict:
    r = _base("privilege_escalation", ts,
              src_ip=_rip(external=False))
    r["failed_login_count"] = random.randint(1, 5)
    r["process_name"] = random.choice(["mimikatz.exe","powershell.exe","cmd.exe"])
    r["label"] = "suspicious"
    return r

def _gen_malware(ts: datetime) -> dict:
    r = _base("malware_detected", ts,
              src_ip=random.choice([_rip(False), _rip(True)]))
    r["process_name"] = random.choice(["meterpreter","mimikatz.exe","nc.exe","powershell.exe"])
    r["label"] = "suspicious"
    return r

def _gen_account_lockout(ts: datetime, src_ip: str = None) -> dict:
    ip = src_ip or _rip(external=True)
    r = _base("account_lockout", ts, src_ip=ip,
              asset=random.choice(["auth-server-01","auth-server-02"]))
    r["failed_login_count"] = random.randint(5, 20)
    r["request_count"] = random.randint(5, 20)
    r["label"] = "suspicious"
    return r

def _gen_lateral_movement(ts: datetime) -> dict:
    r = _base("lateral_movement", ts,
              src_ip=_rip(external=False),
              dst_ip=_rip(external=False))
    r["port"] = random.choice([445, 22, 3389, 135, 5985])
    r["process_name"] = random.choice(["psexec.exe","powershell.exe","wmic.exe"])
    r["label"] = "suspicious"
    return r

def _gen_credential_dump(ts: datetime) -> dict:
    r = _base("credential_dumping", ts, src_ip=_rip(external=False))
    r["process_name"] = "mimikatz.exe"
    r["label"] = "suspicious"
    return r

def _gen_ransomware(ts: datetime, src_ip: str = None) -> dict:
    ip = src_ip or _rip(external=False)
    r = _base("ransomware_activity", ts, src_ip=ip)
    r["request_count"] = random.randint(200, 5000)
    r["bytes_transferred"] = random.randint(1_000_000, 100_000_000)
    r["process_name"] = random.choice(["encrypt.exe","svchost.exe","powershell.exe"])
    r["label"] = "suspicious"
    return r

def _gen_c2(ts: datetime) -> dict:
    r = _base("c2_communication", ts,
              src_ip=_rip(external=False),
              dst_ip=_rip(external=True))
    r["port"] = random.choice([4444, 8080, 443, 1337, 31337])
    r["user_agent"] = random.choice(USER_AGENTS[4:])
    r["bytes_transferred"] = random.randint(100, 50_000)
    r["label"] = "suspicious"
    return r

def _gen_sql_injection(ts: datetime) -> dict:
    r = _base("sql_injection", ts,
              src_ip=_rip(external=True),
              asset=random.choice(["web-server-01","web-server-02","db-server-01"]))
    r["port"] = random.choice([80, 443, 8080, 1433, 3306])
    r["user_agent"] = "sqlmap/1.6"
    r["request_count"] = random.randint(50, 500)
    r["label"] = "suspicious"
    return r

def _gen_xss(ts: datetime) -> dict:
    r = _base("xss_attempt", ts,
              src_ip=_rip(external=True),
              asset=random.choice(["web-server-01","web-server-02","web-server-03"]))
    r["port"] = random.choice([80, 443])
    r["request_count"] = random.randint(10, 200)
    r["user_agent"] = "Nikto/2.1.6"
    r["label"] = "suspicious"
    return r

def _gen_registry_mod(ts: datetime) -> dict:
    r = _base("registry_modification", ts, src_ip=_rip(external=False))
    r["process_name"] = random.choice(["powershell.exe","cmd.exe","regedit.exe","malware.exe"])
    r["label"] = "suspicious"
    return r

# ---------------------------------------------------------------------------
# Campaign simulation — realistic multi-stage attack chains
# ---------------------------------------------------------------------------

def _gen_campaign(start: datetime, n_steps: int = None) -> list:
    """
    Simulate a realistic attack campaign:
    reconnaissance → initial access → lateral movement → exfiltration
    """
    attacker_ip = _rip(external=True)
    target_internal = _rip(external=False)
    n_steps = n_steps or random.randint(3, 8)
    records = []
    ts = start

    stages = random.choice([
        ["port_scan", "brute_force", "privilege_escalation", "lateral_movement", "data_exfiltration"],
        ["port_scan", "sql_injection", "privilege_escalation", "credential_dumping", "c2_communication"],
        ["brute_force", "malware_detected", "c2_communication", "ransomware_activity"],
        ["xss_attempt", "privilege_escalation", "credential_dumping", "lateral_movement"],
        ["port_scan", "brute_force", "account_lockout", "lateral_movement", "data_exfiltration"],
    ])

    for stage in stages[:n_steps]:
        ts += timedelta(minutes=random.randint(1, 20))
        if stage == "port_scan":
            records.append(_gen_port_scan(ts, src_ip=attacker_ip))
        elif stage == "brute_force":
            for _ in range(random.randint(2, 5)):
                ts += timedelta(seconds=random.randint(30, 300))
                records.append(_gen_brute_force(ts, src_ip=attacker_ip))
        elif stage == "account_lockout":
            records.append(_gen_account_lockout(ts, src_ip=attacker_ip))
        elif stage == "sql_injection":
            records.append(_gen_sql_injection(ts))
        elif stage == "xss_attempt":
            records.append(_gen_xss(ts))
        elif stage == "privilege_escalation":
            records.append(_gen_priv_esc(ts))
        elif stage == "lateral_movement":
            for _ in range(random.randint(2, 4)):
                ts += timedelta(minutes=random.randint(1, 5))
                records.append(_gen_lateral_movement(ts))
        elif stage == "credential_dumping":
            records.append(_gen_credential_dump(ts))
        elif stage == "malware_detected":
            records.append(_gen_malware(ts))
        elif stage == "c2_communication":
            for _ in range(random.randint(3, 8)):
                ts += timedelta(minutes=random.randint(1, 15))
                records.append(_gen_c2(ts))
        elif stage == "data_exfiltration":
            records.append(_gen_data_exfiltration(ts))
        elif stage == "ransomware_activity":
            for _ in range(random.randint(2, 5)):
                ts += timedelta(minutes=random.randint(1, 10))
                records.append(_gen_ransomware(ts))

    return records


# ---------------------------------------------------------------------------
# Main generator
# ---------------------------------------------------------------------------

def generate_synthetic_dataset(
    n_normal: int = 30_000,
    n_suspicious: int = 10_000,
    n_campaigns: int = 200,
    output_path: Optional[Path] = None,
) -> pd.DataFrame:
    """
    Generate a large synthetic cybersecurity log dataset.

    Parameters
    ----------
    n_normal    : number of normal activity records
    n_suspicious: number of individual suspicious event records
    n_campaigns : number of multi-stage attack campaigns to simulate
    output_path : if given, saves CSV to this path

    Returns
    -------
    pd.DataFrame — sorted by timestamp

    Label assignment
    ----------------
    'normal'    : routine user operations with low failure counts
    'suspicious': events matching known attack patterns or thresholds
    Labels are rule-based, not from ground-truth threat intelligence.
    """
    logger.info(
        "Generating dataset: %d normal + %d suspicious + %d campaigns",
        n_normal, n_suspicious, n_campaigns,
    )

    end_time   = datetime(2024, 12, 31, 23, 59, 59)
    start_time = datetime(2024, 1, 1, 0, 0, 0)  # full year

    records = []

    # ---- Normal records ----
    normal_gens = [
        _gen_login_success, _gen_file_access, _gen_http_request,
        _gen_dns_query, _gen_vpn, _gen_config_change, _gen_process_creation,
    ]
    for _ in range(n_normal):
        ts = _rts(start_time, end_time)
        records.append(random.choice(normal_gens)(ts))

    # ---- Individual suspicious records ----
    susp_gens = [
        _gen_brute_force, _gen_port_scan, _gen_data_exfiltration,
        _gen_priv_esc, _gen_malware, _gen_account_lockout,
        _gen_lateral_movement, _gen_credential_dump, _gen_ransomware,
        _gen_c2, _gen_sql_injection, _gen_xss, _gen_registry_mod,
    ]
    # Weight heavier attacks less frequently (realistic distribution)
    weights = [0.18, 0.15, 0.08, 0.08, 0.08, 0.10,
               0.07, 0.05, 0.04, 0.06, 0.06, 0.06, 0.05]
    campaign_ips = [_rip(external=True) for _ in range(20)]

    for _ in range(n_suspicious):
        ts  = _rts(start_time, end_time)
        gen = random.choices(susp_gens, weights=weights, k=1)[0]
        if gen == _gen_brute_force and random.random() < 0.3:
            records.append(gen(ts, src_ip=random.choice(campaign_ips)))
        elif gen == _gen_port_scan and random.random() < 0.3:
            records.append(gen(ts, src_ip=random.choice(campaign_ips)))
        else:
            records.append(gen(ts))

    # ---- Attack campaigns (multi-stage, realistic chains) ----
    for _ in range(n_campaigns):
        ts = _rts(start_time, end_time - timedelta(hours=6))
        campaign_records = _gen_campaign(ts)
        records.extend(campaign_records)

    # ---- Build DataFrame ----
    df = pd.DataFrame(records)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df = df.sort_values("timestamp").reset_index(drop=True)

    total       = len(df)
    n_susp_real = (df["label"] == "suspicious").sum()
    n_norm_real = (df["label"] == "normal").sum()

    logger.info(
        "Dataset ready: %d total  |  normal=%d (%.1f%%)  suspicious=%d (%.1f%%)",
        total, n_norm_real, 100*n_norm_real/total,
        n_susp_real, 100*n_susp_real/total,
    )

    if output_path is not None:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        df.to_csv(output_path, index=False)
        size_mb = output_path.stat().st_size / (1024 * 1024)
        logger.info("Saved to %s  (%.2f MB)", output_path, size_mb)

    return df
