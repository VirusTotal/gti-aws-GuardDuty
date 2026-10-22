import os
import re
import json
import boto3
import ipaddress
from typing import Callable
from datetime import datetime, timezone, timedelta
from urllib3 import PoolManager
from botocore.exceptions import ClientError


class HTTPRequestError(Exception):
    """Custom exception for HTTP request failures."""

    pass


class APIKeyNotFound(Exception):
    """Custom exception for HTTP request failures."""

    pass


# Constants
IP_ADDRESS = "ip_address"
DOMAIN = "domain"
MAX_ENTITY_LINES_PER_FILE = 1000
MAX_IP_LINES_PER_FILE = 250000

# Max number of files supported by GuardDuty
MAX_OUTPUT_FILES = 6

# Max Lookback days limit
MAX_LOOKBACK_DAYS = 5

# Max supported page size of IOC stream
MAX_IOC_PAGE_SIZE = 40

# Max supported page size of threat list
MAX_THREAT_LIST_PAGE_SIZE = 4000

# Track which files get written during this execution
WRITTEN_FILES: set[str] = set()

# Track invalid IOCs during execution
INVALID_IP_IOCS: set[str] = set()
INVALID_DOMAIN_IOCS: set[str] = set()

# Regex for domain / wildcard domain validation
DOMAIN_REGEX = re.compile(
    r"^(?:\*\.)?"                       # optional wildcard
    r"(?:[a-zA-Z0-9]"                   # label start
    r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"  # middle labels
    r"[a-zA-Z]{2,}$"                    # TLD
)


# ---------------------------------------------------------------------
# CONFIG (from environment)
# ---------------------------------------------------------------------
CONFIG = {
    "secret_name": os.environ.get("SECRET_NAME"),
    "region": os.environ.get("REGION"),
    "s3_bucket": os.environ.get("S3_BUCKET"),
    "checkpoint_key": "gti-checkpoint.json",
    "entity_files": os.environ.get("ENTITY_FILES", ""),
    "ip_files": os.environ.get("IP_FILES", ""),
    "threat_lists": os.environ.get("THREAT_LISTS", ""),
    "severity_level": os.environ.get("SEVERITY_LEVEL", "VERDICT_MALICIOUS"),
    "lookback_days": os.environ.get("LOOKBACK_DAYS", str(MAX_LOOKBACK_DAYS)),
}

# External URLs
IOC_STREAM_URL = "https://www.virustotal.com/api/v3/ioc_stream"
LIST_CATEGORIZED_THREATS_URL = "https://www.virustotal.com/api/v3/threat_lists"

# NOTE: GuardDuty supports max 6 files, each max 35 MB
MAX_FILE_SIZE_BYTES = 35 * 1024 * 1024

# Comma-separated S3 object keys passed via env
ENTITY_FILES = [f.strip() for f in CONFIG["entity_files"].split(",") if f.strip()]
IP_FILES = [f.strip() for f in CONFIG["ip_files"].split(",") if f.strip()]

# Possible values: [ VERDICT_BENIGN, VERDICT_UNDETECTED, VERDICT_SUSPICIOUS, VERDICT_MALICIOUS, VERDICT_UNKNOWN ]
VALID_SEVERITY_FILTERS = ["VERDICT_BENIGN", "VERDICT_UNDETECTED", "VERDICT_SUSPICIOUS", "VERDICT_MALICIOUS", "VERDICT_UNKNOWN"]
SEVERITY_FILTER = [s.strip() for s in CONFIG["severity_level"].split(",") if s.strip() in VALID_SEVERITY_FILTERS]

# AWS clients
secrets = boto3.client("secretsmanager", region_name=CONFIG["region"])
s3 = boto3.client("s3", region_name=CONFIG["region"])
gd = boto3.client("guardduty", region_name=CONFIG["region"])


# ---------------------------------------------------------------------
# UTILITY FUNCTIONS
# ---------------------------------------------------------------------
def get_api_key() -> str:
    """Read secret from secret manager."""
    return secrets.get_secret_value(SecretId=CONFIG["secret_name"])["SecretString"]


def is_valid_ipv4_or_cidr(value: str) -> bool:
    """Validate IPv4 or IPv4 CIDR."""
    try:
        ipaddress.IPv4Network(value, strict=False)
        return True
    except Exception:
        INVALID_IP_IOCS.add(value)
        return False


def is_valid_domain(value: str) -> bool:
    """Validate domain or wildcard domain."""
    if value.startswith(("http://", "https://")):   # NOSONAR - checking for protocol prefix to reject, not using HTTP
        INVALID_DOMAIN_IOCS.add(value)
        return False

    if DOMAIN_REGEX.fullmatch(value):
        return True

    INVALID_DOMAIN_IOCS.add(value)
    return False

def read_s3_lines(bucket: str, file_keys: list[str]) -> set:
    """
    Read line-separated IOC files from S3 and return a unique set.
    Missing files are treated as empty.
    """
    all_iocs: set[str] = set()

    for key in file_keys:
        try:
            obj = s3.get_object(Bucket=bucket, Key=key)
            lines = obj["Body"].read().decode("utf-8").splitlines()
            all_iocs.update(lines)
            print(f"[INFO] Loaded {len(lines)} records from S3 file: {key}")

        except s3.exceptions.NoSuchKey:
            print(f"[WARN] S3 file not found (skipping): {key}")

    return all_iocs


def write_s3_lines(bucket: str, key: str, lines: list[str]):
    """
    Write line-separated IOCs to S3.
    """
    body = "\n".join(lines) + "\n"
    s3.put_object(Bucket=bucket, Key=key, Body=body)

    size_mb = len(body.encode("utf-8")) / (1024 * 1024)
    print(
        f"[INFO] Updated S3 file: {key} | "
        f"Records: {len(lines)} | Size: {size_mb:.2f} MB"
    )


def update_invalid_ioc_file(ioc_type: str, values: set[str]):
    """
    Write invalid IOCs found during this execution to S3.
    """
    # If no invalid ioc found, skip
    if not values:
        return

    key = f"invalid_iocs/invalid_{ioc_type}.txt"
    iocs = read_s3_lines(CONFIG["s3_bucket"], [key])
    if not (values - iocs):
        return

    iocs.update(values)
    write_s3_lines(CONFIG["s3_bucket"], key, iocs)


def read_checkpoint(bucket: str, key: str) -> dict:
    """Load checkpoint for cursor + notification timestamp."""
    try:
        obj = s3.get_object(Bucket=bucket, Key=key)
        return json.loads(obj["Body"].read().decode())
    except ClientError:
        print("[WARN] Checkpoint not found, creating new one.")
        return {}


def write_checkpoint(bucket: str, key: str, data: dict):
    """Write checkpoint JSON back to S3."""
    s3.put_object(Bucket=bucket, Key=key, Body=json.dumps(data))
    print(f"[INFO] Checkpoint saved: {data}")



def get_detector_id() -> str:
    """Retrieve the first GuardDuty detector ID in the region."""
    detectors = gd.list_detectors()["DetectorIds"]
    if not detectors:
        raise RuntimeError("No GuardDuty detector found in the region")
    detector_id = detectors[0]
    print(f"[INFO] Using GuardDuty Detector ID: {detector_id}")
    return detector_id


def _is_written_file(location: str) -> bool:
    """Check if location matches any written file."""
    return any(location.endswith(f) for f in WRITTEN_FILES)


def _activate_entity_set(detector_id: str, entity_set_id: str, location: str, status: str) -> dict | None:
    """Activate a single threat entity set if needed. Returns update info dict if activated, None otherwise."""
    if not _is_written_file(location):
        return None
    
    if status == "ACTIVE":
        print(f"[INFO] Threat ENTITY list already ACTIVE (no action): {location}")
        return None
    
    print(f"[INFO] Activating threat ENTITY list: {location} (current status: {status})")
    gd.update_threat_entity_set(
        DetectorId=detector_id,
        ThreatEntitySetId=entity_set_id,
        Activate=True,
    )
    return {"file": location, "type": "ENTITY", "action": "activated"}


def _activate_intel_set(detector_id: str, intel_set_id: str, location: str, status: str) -> dict | None:
    """Activate a single threat intel set if needed. Returns update info dict if activated, None otherwise."""
    if not _is_written_file(location):
        return None
    
    if status == "ACTIVE":
        print(f"[INFO] Threat IP list already ACTIVE (no action): {location}")
        return None
    
    print(f"[INFO] Activating threat IP list: {location} (current status: {status})")
    gd.update_threat_intel_set(
        DetectorId=detector_id,
        ThreatIntelSetId=intel_set_id,
        Activate=True,
    )
    return {"file": location, "type": "IP", "action": "activated"}


def _process_entity_sets(detector_id: str) -> list:
    """Process and activate threat entity sets."""
    resp = gd.list_threat_entity_sets(DetectorId=detector_id)
    updated = []
    
    for entity_set_id in resp["ThreatEntitySetIds"]:
        details = gd.get_threat_entity_set(
            DetectorId=detector_id,
            ThreatEntitySetId=entity_set_id,
        )
        location = details["Location"]
        status = details.get("Status", "UNKNOWN")
        
        result = _activate_entity_set(detector_id, entity_set_id, location, status)
        if result:
            updated.append(result)
    
    return updated


def _process_intel_sets(detector_id: str) -> list:
    """Process and activate threat intel sets."""
    resp = gd.list_threat_intel_sets(DetectorId=detector_id)
    updated = []
    
    for intel_set_id in resp["ThreatIntelSetIds"]:
        details = gd.get_threat_intel_set(
            DetectorId=detector_id,
            ThreatIntelSetId=intel_set_id,
        )
        location = details["Location"]
        status = details.get("Status", "UNKNOWN")
        
        result = _activate_intel_set(detector_id, intel_set_id, location, status)
        if result:
            updated.append(result)
    
    return updated


def activate_written_threat_lists():
    """
    Activate threat ENTITY lists and threat IP lists that were written in this run,
    only if currently inactive.
    """
    if not WRITTEN_FILES:
        print("[INFO] No files were written in this run. Skipping GuardDuty activation.")
        return []

    detector_id = get_detector_id()
    updated = []

    # 1. Threat ENTITY Lists
    updated.extend(_process_entity_sets(detector_id))

    # 2. Threat IP Lists
    updated.extend(_process_intel_sets(detector_id))

    if not updated:
        print("[INFO] No threat lists required activation.")
    else:
        print(f"[INFO] Activated {len(updated)} threat list(s).")

    return updated


# ---------------------------------------------------------------------
# GTI CLIENT CLASS
# ---------------------------------------------------------------------
class GTIClient:
    """
    A lightweight HTTP client for VirusTotal GTI API.
    Uses urllib3 PoolManager for connection reuse.
    """

    def __init__(self, timeout: float = 30.0):
        global ENTITY_FILES, IP_FILES, SEVERITY_FILTER
        self.timeout = timeout

        api_key = get_api_key()
        if not api_key:
            raise APIKeyNotFound("[ERROR] API key not found in secret manager")

        # Verify lookback days type and limit its value
        try:
            v = int(CONFIG.get("lookback_days"))
        except (TypeError, ValueError):
            print(f"[WARN] Invalid lookback days value: {CONFIG['lookback_days']}")
            v = MAX_LOOKBACK_DAYS

        CONFIG["lookback_days"] = v if 0 <= v <= MAX_LOOKBACK_DAYS else MAX_LOOKBACK_DAYS
        print(f"[INFO] Using lookback days: {CONFIG['lookback_days']}")

        self.http = PoolManager(
            headers={
                "x-apikey": api_key,
                "accept": "application/json",
                "x-tool": "aws guardduty",
            }
        )

        if len(SEVERITY_FILTER) == 0:
            print("[WARN] No valid severity filter provided. Keeping default filter: 'VERDICT_MALICIOUS'")
            SEVERITY_FILTER.append("VERDICT_MALICIOUS")

        if len(ENTITY_FILES) > MAX_OUTPUT_FILES:
            print(
                f"[WARN] GuardDuty does not support more than {MAX_OUTPUT_FILES} threat list files. "
                f"Will take the first {MAX_OUTPUT_FILES} files. {ENTITY_FILES[:MAX_OUTPUT_FILES]}"
            )
            ENTITY_FILES = ENTITY_FILES[:MAX_OUTPUT_FILES]
        
        if len(IP_FILES) > MAX_OUTPUT_FILES:
            print(
                f"[WARN] GuardDuty does not support more than {MAX_OUTPUT_FILES} threat list files. "
                f"Will take the first {MAX_OUTPUT_FILES} files. {IP_FILES[:MAX_OUTPUT_FILES]}"
            )
            IP_FILES = IP_FILES[:MAX_OUTPUT_FILES]

        # Load existing S3 content
        self.current_domains = read_s3_lines(CONFIG["s3_bucket"], ENTITY_FILES)
        self.current_ips = read_s3_lines(CONFIG["s3_bucket"], IP_FILES)

    # ------------------------------------------------------------------
    def get(self, url: str, params: dict | None = None) -> dict:
        """Perform a GET request and return parsed JSON."""
        print(f"[INFO] Requesting URL: {url} | Params: {params}")

        response = self.http.request("GET", url, fields=params, timeout=self.timeout)

        if response.status >= 400:
            message = f"HTTP {response.status}: {response.data.decode(errors='ignore')}"
            print(f"[ERROR] {message}")
            raise HTTPRequestError(message)

        return json.loads(response.data.decode())

    # ------------------------------------------------------------------
    def get_paginated(self, url: str, params: dict | None = None, results_key="data"):
        """
        Generator that automatically fetches paginated GTI responses.
        """
        while url:
            response = self.get(url, params)
            cursor = response.get("meta", {}).get("cursor")

            yield response.get(results_key, []), cursor

            # Pagination - next URL
            url = response.get("links", {}).get("next")
            params = None  # next pages do not need params

    # ------------------------------------------------------------------
    def update_results(self, new_result: set[str], file_keys: list[str], max_lines_per_file: int, ioc_type: str):
        current_result = self.current_domains if ioc_type == DOMAIN else self.current_ips
        if not (new_result - current_result):
            print(f"[INFO] No new iocs ({ioc_type}) found.")
            return

        current_result.update(new_result)
        lines = list(current_result)
        file_iterator = iter(file_keys)

        for i in range(0, len(lines), max_lines_per_file):
            try:
                current_key = next(file_iterator)
                write_s3_lines(CONFIG["s3_bucket"], current_key, lines[i:i+max_lines_per_file])
                WRITTEN_FILES.add(current_key)
            except StopIteration:
                print(f"Exceeded max GuardDuty {ioc_type} files ({len(file_keys)} configured)")
                file_key = f"exceeded_{ioc_type}.txt"

                # Dump extra ips in seperate file to keep track
                existing = read_s3_lines(CONFIG["s3_bucket"], [file_key])
                existing.update(lines[i:])
                write_s3_lines(CONFIG["s3_bucket"], file_key, existing)
                break

        # Update current result
        if ioc_type == DOMAIN:
            self.current_domains = current_result
        else:
            self.current_ips = current_result

    # ------------------------------------------------------------------
    def _process_ioc_item(self, item: dict, checkpoint_date: int, validation_func: Callable) -> tuple[int, str | None]:
        """
        Process a single IOC item and return updated checkpoint_date and IOC value if valid.
        Returns: (updated_checkpoint_date, ioc_value or None)
        """
        n_date = item.get("context_attributes", {}).get("notification_date")
        updated_checkpoint_date = checkpoint_date

        # track latest notification date
        if n_date and n_date > checkpoint_date:
            updated_checkpoint_date = n_date

        verdict = item["attributes"]["gti_assessment"]["verdict"]["value"]
        ioc_id = item["id"]
        
        if verdict in SEVERITY_FILTER and validation_func(ioc_id):
            return updated_checkpoint_date, ioc_id
        
        return updated_checkpoint_date, None

    def _update_ioc_results(self, new_results: set[str], entity_type: str):
        """Update results based on entity type."""
        if entity_type == IP_ADDRESS:
            self.update_results(new_results, IP_FILES, MAX_IP_LINES_PER_FILE, IP_ADDRESS)
        else:
            self.update_results(new_results, ENTITY_FILES, MAX_ENTITY_LINES_PER_FILE, DOMAIN)

    def fetch_ioc_stream(self, checkpoint: dict, entity_type: str, validation_func: Callable):
        """
        Fetch indicators from GTI IOC Stream in paginated form.
        Updates checkpoint only after all pages are processed.
        """
        date_key = f"{entity_type}_last_notification_date"

        lookback_date = datetime.now(timezone.utc) - timedelta(days=CONFIG["lookback_days"])

        # No checkpoint data available - use lookback days for initial fetch
        checkpoint_date = checkpoint.get(date_key) or 0
        last_date = checkpoint_date or int(lookback_date.timestamp())

        params = {
            "limit": MAX_IOC_PAGE_SIZE,
            "order": "date+",
            "filter": f"entity_type:{entity_type}",
        }
        formatted = datetime.fromtimestamp(last_date).strftime("%Y-%m-%dT%H:%M:%S")
        params["filter"] = f"{params['filter']} date:{formatted}+"

        print(f"[INFO] Fetching IOC Stream ({entity_type}) | last_date={last_date}")
        new_results = set()

        # Pagination loop
        for page, next_cursor in self.get_paginated(IOC_STREAM_URL, params):
            print(
                f"[DEBUG] Fetched page with {len(page)} items | next_cursor={next_cursor}"
            )

            for item in page:
                checkpoint_date, ioc_value = self._process_ioc_item(item, checkpoint_date, validation_func)
                if ioc_value:
                    new_results.add(ioc_value)

        # Update checkpoint after full processing
        checkpoint[date_key] = checkpoint_date or None

        self._update_ioc_results(new_results, entity_type)
        write_checkpoint(CONFIG["s3_bucket"], CONFIG["checkpoint_key"], checkpoint)

        print(f"[INFO] IOC Stream ({entity_type}) fetch completed.")

    # ------------------------------------------------------------------
    def _get_start_timestamp(self, checkpoint: dict, category: str) -> str:
        """Determine the starting timestamp for threat list fetching."""
        checkpoint_ts = checkpoint.get("threat_lists", {}).get(category)
        if checkpoint_ts:
            return checkpoint_ts
        
        # Use lookback days if no checkpoint
        start_date = datetime.now(timezone.utc) - timedelta(days=CONFIG["lookback_days"])
        return start_date.strftime("%Y%m%d%H")

    def _process_threat_list_iocs(self, iocs: list) -> tuple[set[str], set[str]]:
        """Process IOCs from threat list response and return (ip_ids, domain_ids)."""
        domain_ids = set()
        ip_ids = set()

        for ioc in iocs:
            data = ioc["data"]
            verdict = data["attributes"]["gti_assessment"]["verdict"]["value"]

            if verdict not in SEVERITY_FILTER:
                continue

            ioc_id = data["id"]
            if data["type"] == IP_ADDRESS:
                if is_valid_ipv4_or_cidr(ioc_id):
                    ip_ids.add(ioc_id)
            elif is_valid_domain(ioc_id):
                domain_ids.add(ioc_id)

        return ip_ids, domain_ids

    def _process_single_hour_threat_list(self, category: str, hour_ts: str, checkpoint: dict):
        """Process threat list data for a single hour."""
        url = f"{LIST_CATEGORIZED_THREATS_URL}/{category}/{hour_ts}?type={IP_ADDRESS},{DOMAIN}&limit={MAX_THREAT_LIST_PAGE_SIZE}"
        print(f"[INFO] Fetching threat list: {category}, timestamp={hour_ts}")

        response = self.get(url)

        # Fail fast if GTI response structure changes
        if "iocs" not in response:
            raise RuntimeError(
                f"Unexpected GTI threat-list response format for category '{category}': "
                f"missing 'iocs' key"
            )

        ip_ids, domain_ids = self._process_threat_list_iocs(response["iocs"])

        # Update checkpoint for threat list category
        if "threat_lists" not in checkpoint:
            checkpoint["threat_lists"] = {}
        checkpoint["threat_lists"][category] = hour_ts

        self.update_results(ip_ids, IP_FILES, MAX_IP_LINES_PER_FILE, IP_ADDRESS)
        self.update_results(domain_ids, ENTITY_FILES, MAX_ENTITY_LINES_PER_FILE, DOMAIN)
        write_checkpoint(CONFIG["s3_bucket"], CONFIG["checkpoint_key"], checkpoint)

    def fetch_single_threat_list(self, category, time_stamp, checkpoint: dict):
        """Fetch IOC values for a single threat list category."""
        start_ts = self._get_start_timestamp(checkpoint, category)

        # Convert timestamps to datetime objects for comparison
        current_dt = datetime.strptime(time_stamp, "%Y%m%d%H")
        start_dt = datetime.strptime(start_ts, "%Y%m%d%H")

        # Fetch data for each hour from start_ts to time_stamp
        current = start_dt
        while current <= current_dt:
            hour_ts = current.strftime("%Y%m%d%H")
            self._process_single_hour_threat_list(category, hour_ts, checkpoint)
            current += timedelta(hours=1)

    # ------------------------------------------------------------------
    def fetch_threat_list_iocs(self, checkpoint: dict):
        """
        Fetch categorized threat lists.
        Only pulls hourly threat lists up to 2 hours before the current UTC hour.
        """

        current_ts = (datetime.now(timezone.utc) - timedelta(hours=2)).strftime("%Y%m%d%H")
        print(f"[INFO] Fetching threat lists | timestamp={current_ts}")

        categories: set[str] = set()

        # Fetch category list
        for page, _ in self.get_paginated(LIST_CATEGORIZED_THREATS_URL):
            categories.update([i["id"] for i in page])

        if CONFIG["threat_lists"]:
            requested = {
                x.strip() for x in CONFIG["threat_lists"].split(",") if x.strip()
            }
            invalid = requested - categories

            if invalid:
                print(f"[WARNING] Unknown threat list names ignored: {invalid}")

            categories = list(requested & categories)

        print(f"[DEBUG] Threat list categories selected: {categories}")

        for category in categories:
            self.fetch_single_threat_list(category, current_ts, checkpoint)


# ---------------------------------------------------------------------
# MAIN LAMBDA HANDLER
# ---------------------------------------------------------------------
def lambda_handler(event, context):
    print("[INFO] ===== GTI IOC Sync Lambda Starting =====")

    try:
        checkpoint = read_checkpoint(CONFIG["s3_bucket"], CONFIG["checkpoint_key"])

        if not ENTITY_FILES or not IP_FILES:
            raise ValueError(
                f"{'Entity files missing. ' if not ENTITY_FILES else ''}"
                f"{'IP files missing.' if not IP_FILES else ''}"
            )

        # Initialize GTI client
        gti_client = GTIClient()

        # Fetch IOC Stream IOCs (For Guardduty, we only require ip & domain IOCs)
        gti_client.fetch_ioc_stream(checkpoint, entity_type=DOMAIN, validation_func=is_valid_domain)
        gti_client.fetch_ioc_stream(checkpoint, entity_type=IP_ADDRESS, validation_func=is_valid_ipv4_or_cidr)

        # Fetch categorized threat lists
        gti_client.fetch_threat_list_iocs(checkpoint)

        # Writing invalid iocs to s3 file
        update_invalid_ioc_file(IP_ADDRESS, INVALID_IP_IOCS)
        update_invalid_ioc_file(DOMAIN, INVALID_DOMAIN_IOCS)

        # Activate GuardDuty threat lists if any files were updated
        activated = activate_written_threat_lists()

    except Exception as e:
        print(f"[ERROR] {str(e)}")
        return {"error": str(e)}

    print("[INFO] ✔ IOC Sync Completed Successfully")

    return {
        "total_domains": len(gti_client.current_domains),
        "total_ips": len(gti_client.current_ips),
        "WRITTEN_FILES": list(WRITTEN_FILES),
        "activated_threat_lists": activated,
    }
