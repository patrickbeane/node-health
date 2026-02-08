#!/usr/bin/env python3

"""
Node Health Check and Failover
Monitors service health and automatically changes DNS records between primary and mirror servers.
"""

from datetime import datetime, UTC, timedelta
import requests
import os
import sys
import argparse
from dotenv import load_dotenv
import time

# ----------------------------
# Config
# ----------------------------

SERVICES = {
    "example-service": {
        "dns_name": "example-service.example.com",
        "primary": {
            "url": "https://primary.example-service.example.com/health",
            "ip": "1.2.3.4",
            "ipv6": "2001:db8::1",
            "check": "http"
        },
        "mirror": {
            "url": "https://mirror.example-service.example.com/health",
            "ip": "5.6.7.8",
            "ipv6": "2001:db8::2",
            "check": "http"
        }
    }
}

STALE_THRESHOLD = timedelta(minutes=20)
HTTP_TIMEOUT = 2
CF_TIMEOUT = 10
DNS_TTL = 60
MIN_SWITCH_INTERVAL = timedelta(minutes=5)

# ----------------------------
# Globals
# ----------------------------

DRY_RUN = False
VERBOSE = False

# ----------------------------
# Helpers
# ----------------------------

def log(msg: str, level: str = "INFO"):
    ts = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    print(f"[{ts}] [{level}] {msg}")

def debug(msg: str):
    if VERBOSE:
        log(msg, "DEBUG")

def parse_iso_z(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))

def validate_services():
    """Validate SERVICES configuration at startup"""
    required_fields = ["dns_name", "primary", "mirror"]
    endpoint_fields = ["url", "ip", "check"]

    for name, service in SERVICES.items():
        for field in required_fields:
            if field not in service:
                log(f"Service '{name}' missing required field: {field}", "ERROR")
                return False

        for role in ["primary", "mirror"]:
            for field in endpoint_fields:
                if field not in service[role]:
                    log(f"Service '{name}' {role} missing field: {field}", "ERROR")
                    return False

            check_type = service[role]["check"]
            if check_type not in ["http", "intel", "threats"]:
                log(f"Service '{name}' {role} has invalid check type: {check_type}", "ERROR")
                return False

    return True

def check_health(service: dict, role: str) -> bool:
    endpoint = service[role]
    check_type = endpoint["check"]

    debug(f"Running {check_type} health check on {endpoint['url']}")

    if check_type == "intel":
        return check_intel_health(endpoint["url"])
    elif check_type == "threats":
        return check_threats_health(endpoint["url"])
    elif check_type == "http":
        return check_http_health(endpoint["url"])

    return False

def check_http_health(url: str) -> bool:
    try:
        r = requests.get(url, timeout=HTTP_TIMEOUT)
        return r.status_code == 200
    except requests.exceptions.Timeout:
        debug(f"HTTP health check timed out: {url}")
        return False
    except Exception as e:
        debug(f"HTTP health check failed: {url} - {e}")
        return False

def check_intel_health(url: str) -> bool:
    for attempt in range(3):
        try:
            r = requests.get(url, timeout=HTTP_TIMEOUT)

            if r.status_code != 200:
                debug(f"Intel check attempt {attempt+1} failed: HTTP {r.status_code}")
                time.sleep(2)
                continue

            data = r.json()

            total_bans = data.get("total_bans")
            top_countries = data.get("top_countries")

            if not isinstance(total_bans, int) or total_bans < 0:
                debug(f"Intel check attempt {attempt+1}: invalid total_bans={total_bans}")
                time.sleep(2)
                continue

            if not isinstance(top_countries, list):
                debug(f"Intel check attempt {attempt+1}: invalid top_countries type")
                time.sleep(2)
                continue

            if len(top_countries) == 0:
                debug("Intel API reachable but returned empty data (degraded)")

            return True

        except Exception as e:
            debug(f"Intel health check attempt {attempt+1} error: {e}")
            time.sleep(2)

    debug("Intel health check failed after 3 attempts")
    return False

def check_threats_health(url: str) -> bool:
    try:
        r = requests.get(url, timeout=HTTP_TIMEOUT)
        if r.status_code != 200:
            debug(f"Threats check failed: HTTP {r.status_code}")
            return False

        data = r.json()

        if "generated_at" not in data or "threats" not in data:
            debug("Threats check failed: missing required top-level fields")
            return False

        if not isinstance(data["threats"], list):
            debug("Threats check failed: threats is not a list")
            return False

        try:
            generated_at = parse_iso_z(data["generated_at"])
            age = datetime.now(UTC) - generated_at
            if age > STALE_THRESHOLD:
                debug(f"Threats API reachable but data is stale ({age})")
        except Exception as e:
            debug(f"Threats check warning: invalid generated_at ({e})")

        malformed = 0
        for t in data["threats"][:10]:
            if not isinstance(t, dict) or "ip" not in t:
                malformed += 1

        if malformed:
            debug(f"Threats check warning: {malformed} malformed threat entries")

        return True

    except Exception as e:
        debug(f"Threats health check failed: {url} - {e}")
        return False


# ----------------------------
# Env / Setup
# ----------------------------

def load_config():
    if not os.path.exists('.env'):
        log(".env file not found. Please copy .env.example to .env and fill in your credentials", "ERROR")
        return None

    load_dotenv()

    CF_API_TOKEN = os.getenv("CF_API_TOKEN")
    CF_ZONE_ID = os.getenv("CF_ZONE_ID")
    DISCORD_WEBHOOK = os.getenv("DISCORD_WEBHOOK")

    if not CF_API_TOKEN or not CF_ZONE_ID:
        log("Cloudflare credentials missing from .env", "ERROR")
        return None

    if not DISCORD_WEBHOOK:
        log("Discord webhook missing from .env", "WARN")

    return {
        "CF_API_TOKEN": CF_API_TOKEN,
        "CF_ZONE_ID": CF_ZONE_ID,
        "DISCORD_WEBHOOK": DISCORD_WEBHOOK
    }

# ----------------------------
# Cloudflare DNS helpers
# ----------------------------

def get_cf_headers(api_token: str):
    return {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json"
    }

def cf_api_request(method: str, url: str, headers: dict, *, params: dict | None = None,
                   json: dict | None = None, timeout: int = CF_TIMEOUT):
    r = requests.request(method, url, headers=headers, params=params, json=json, timeout=timeout)
    r.raise_for_status()
    try:
        data = r.json()
    except Exception as e:
        raise RuntimeError(f"Cloudflare API returned non-JSON response: {e}") from e

    if not data.get("success", False):
        errors = data.get("errors") or data.get("messages") or "unknown error"
        raise RuntimeError(f"Cloudflare API error: {errors}")

    return data

def get_dns_record(dns_name: str, zone_id: str, headers: dict):
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
    data = cf_api_request("GET", url, headers, params={"type": "A", "name": dns_name})
    records = data["result"]
    return records[0] if records else None

def update_dns_record(record_id: str, dns_name: str, ip: str, record_type: str, zone_id: str, headers: dict):
    if DRY_RUN:
        log(f"[DRY-RUN] Would update {record_type} record {dns_name} to {ip}", "INFO")
        return

    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}"
    payload = {
        "type": record_type,
        "name": dns_name,
        "content": ip,
        "ttl": DNS_TTL,
        "proxied": False
    }

    for attempt in range(2):
        try:
            cf_api_request("PUT", url, headers, json=payload)
            return
        except requests.exceptions.RequestException as e:
            if attempt == 1:
                log(f"Failed to update DNS record after 2 attempts: {e}", "ERROR")
                raise
            debug(f"DNS update attempt {attempt + 1} failed, retrying...")

def get_aaaa_record(dns_name: str, zone_id: str, headers: dict):
    data = cf_api_request(
        "GET",
        f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records",
        headers,
        params={"type": "AAAA", "name": dns_name}
    )
    records = data["result"]
    return records[0] if records else None

def create_aaaa_record(dns_name: str, ipv6: str, zone_id: str, headers: dict):
    if DRY_RUN:
        log(f"[DRY-RUN] Would create AAAA record {dns_name} to {ipv6}", "INFO")
        return

    cf_api_request(
        "POST",
        f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records",
        headers=headers,
        json={"type": "AAAA", "name": dns_name, "content": ipv6, "ttl": DNS_TTL, "proxied": False}
    )

def delete_dns_record(record_id: str, zone_id: str, headers: dict):
    if DRY_RUN:
        log(f"[DRY-RUN] Would delete DNS record {record_id}", "INFO")
        return

    cf_api_request(
        "DELETE",
        f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}",
        headers=headers
    )

# ----------------------------
# Discord Notify
# ----------------------------

def notify(message: str, webhook_url: str):
    if not webhook_url:
        return

    if DRY_RUN:
        log(f"[DRY-RUN] Would send Discord notification: {message}", "INFO")
        return

    try:
        r = requests.post(webhook_url,json={"text": message}, timeout=3)
        if r.status_code not in [200, 204]:
            log(f"Discord notification failed: HTTP {r.status_code}", "WARN")
    except Exception as e:
        log(f"Discord notification failed: {e}", "WARN")

# ----------------------------
# State Management
# ----------------------------

STATE_DIR = os.path.expanduser("~/.local/state/node-health")
LOCK_FILE = os.path.join(STATE_DIR, "LOCK")

os.makedirs(STATE_DIR, exist_ok=True)

def last_switch_time(service: str):
    path = os.path.join(STATE_DIR, f"{service}.last_switch")
    if not os.path.exists(path):
        return None
    try:
        return datetime.fromisoformat(open(path).read().strip())
    except Exception as e:
        log(f"Failed to read last switch time for {service}: {e}", "WARN")
        return None

def record_switch(service: str):
    if DRY_RUN:
        return

    path = os.path.join(STATE_DIR, f"{service}.last_switch")
    try:
        with open(path, "w") as f:
            f.write(datetime.now(UTC).isoformat())
    except Exception as e:
        log(f"Failed to record switch time for {service}: {e}", "ERROR")

# ----------------------------
# Main Logic
# ----------------------------

def main():
    global DRY_RUN, VERBOSE

    parser = argparse.ArgumentParser(description="Service health check and DNS failover")
    parser.add_argument("--dry-run", action="store_true", help="Allow a run to show what would be done without making changes")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    args = parser.parse_args()

    DRY_RUN = args.dry_run
    VERBOSE = args.verbose

    if DRY_RUN:
        log("Running in DRY-RUN mode - no changes will be made", "INFO")

    if not validate_services():
        log("Service configuration validation failed", "ERROR")
        sys.exit(1)

    config = load_config()
    if not config:
        sys.exit(1)

    cf_headers = get_cf_headers(config["CF_API_TOKEN"])

    if os.path.exists(LOCK_FILE) and not DRY_RUN:
        log("Failover locked — exiting (remove LOCK file to resume)", "WARN")
        return

    for name, service in SERVICES.items():
        try:
            log(f"Checking service: {name}", "INFO")

            primary_ok = check_health(service, "primary")
            mirror_ok = check_health(service, "mirror")

            log(f"Primary healthy: {primary_ok}", "INFO")
            log(f"Mirror healthy: {mirror_ok}", "INFO")

            if primary_ok:
                desired_ip = service["primary"]["ip"]
                desired_ipv6 = service["primary"].get("ipv6")
                desired_label = "PRIMARY"
            elif mirror_ok:
                desired_ip = service["mirror"]["ip"]
                desired_ipv6 = service["mirror"].get("ipv6")
                desired_label = "MIRROR"
            else:
                log(f"{name}: both endpoints unhealthy - skipping", "ERROR")
                try:
                    aaaa = get_aaaa_record(service["dns_name"], config["CF_ZONE_ID"], cf_headers)
                    if aaaa:
                        delete_dns_record(aaaa["id"], config["CF_ZONE_ID"], cf_headers)
                        log(f"{name}: removed IPv6 due to total outage", "INFO")
                except Exception as e:
                    log(f"{name}: failed to clean up IPv6 record: {e}", "ERROR")
                continue

            debug(f"Desired IPv4: {desired_ip} ({desired_label})")
            debug(f"Desired IPv6: {desired_ipv6 or 'None'} ({desired_label})")

            try:
                record = get_dns_record(service["dns_name"], config["CF_ZONE_ID"], cf_headers)
                aaaa = get_aaaa_record(service["dns_name"], config["CF_ZONE_ID"], cf_headers)
            except Exception as e:
                log(f"{name}: DNS query failed: {e}", "ERROR")
                continue

            if not record:
                log(f"{name}: A record not found", "ERROR")
                continue

            current_ip = record["content"]
            current_ipv6 = aaaa["content"] if aaaa else None

            ipv4_change_needed = (current_ip != desired_ip)
            ipv6_change_needed = (current_ipv6 != desired_ipv6)
            change_needed = ipv4_change_needed or ipv6_change_needed

            if change_needed:
                last = last_switch_time(name)
                if last:
                    age = datetime.now(UTC) - last
                    if age < MIN_SWITCH_INTERVAL:
                        if ((current_ip == service["primary"]["ip"] and primary_ok) or
                            (current_ip == service["mirror"]["ip"] and mirror_ok)):
                            remaining = MIN_SWITCH_INTERVAL - age
                            log(f"{name}: cooldown active ({remaining}) - staying put", "INFO")
                            continue

            if ipv4_change_needed:
                log(f"{name}: updating IPv4 → {desired_label} ({desired_ip})", "INFO")
                update_dns_record(record["id"], service["dns_name"], desired_ip, "A", config["CF_ZONE_ID"], cf_headers)

            if desired_ipv6:
                if not aaaa:
                    log(f"{name}: creating IPv6 → {desired_label}", "INFO")
                    create_aaaa_record(service["dns_name"], desired_ipv6, config["CF_ZONE_ID"], cf_headers)
                elif ipv6_change_needed:
                    log(f"{name}: updating IPv6 → {desired_label} ({desired_ipv6})", "INFO")
                    update_dns_record(aaaa["id"], service["dns_name"], desired_ipv6, "AAAA", config["CF_ZONE_ID"], cf_headers)
            else:
                if aaaa:
                    log(f"{name}: removing IPv6 (target has none)", "INFO")
                    delete_dns_record(aaaa["id"], config["CF_ZONE_ID"], cf_headers)

            if change_needed:
                record_switch(name)

                ipv6_info = f" | IPv6: {desired_ipv6}" if desired_ipv6 else ""
                notify(
                    f"🚨 **{name.upper()}** failover\n"
                    f"→ Switched to **{desired_label}**\n"
                    f"IPv4: `{desired_ip}`{ipv6_info}\n"
                    f"Primary healthy: {primary_ok}\n"
                    f"Mirror healthy: {mirror_ok}",
                    config["DISCORD_WEBHOOK"]
                )

                log(f"{name}: DNS updated → {desired_label}", "INFO")
            else:
                log(f"{name}: DNS already correct ({desired_label})", "INFO")

        except Exception as e:
            log(f"Critical failure processing {name}: {e}", "ERROR")
            continue

if __name__ == "__main__":
    main()
