# GTI → AWS GuardDuty Integration

Automated integration between **Google Threat Intelligence (GTI)** and **AWS GuardDuty** for continuous threat list ingestion.

## Overview

This solution deploys a Lambda function that:

1. Fetches **IP addresses** and **domains** from GTI APIs using GTI IOC Stream API and GTI Categorized Threat Lists API
2. Stores IOCs in S3-backed threat list files
3. Registers and activates **ThreatIntelSets** (IPs) and **ThreatEntitySets** (domains) in GuardDuty
4. Maintains incremental state via checkpointing
5. Runs on a configurable EventBridge schedule

---

## Deployment

### Prerequisites
- AWS CLI configured with appropriate permissions
- Valid Google Threat Intelligence API key
- GuardDuty enabled in target region (or permissions to create detector)

### AWS CLI

```bash
aws cloudformation deploy \
  --template-file cloud-formation.yaml \
  --stack-name gti-guardduty-integration \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    SecretValue=<YOUR_GTI_API_KEY>
```

### AWS Console

1. Navigate to **CloudFormation** → **Create stack**
2. Upload `cloud-formation.yaml`
3. Set stack name (e.g., `gti-guardduty-integration`)
4. Enter `SecretValue` (your GTI API key)
5. Acknowledge IAM resource creation
6. Submit and wait for `CREATE_COMPLETE`

**Note:** Initial deployment takes several minutes due to Lambda layer creation and custom resource execution.

---

## Configuration Parameters

### Required
| Parameter | Description |
|-----------|-------------|
| `SecretValue` | Google Threat Intelligence (GTI) API key |

### Configuration
| Parameter | Default | Description |
|-----------|---------|-------------|
| `BucketName` | `gti-guard-duty-integration` | S3 bucket name to create (must be globally unique) |
| `SecretKey` | `GTI_API_KEY` | Secrets Manager secret name to create (must be globally unique) |
| `ScheduleExpression` | `cron(0 * * * ? *)` | EventBridge cron expression for Lambda schedule |

### Filtering
| Parameter | Default | Description |
|-----------|---------|-------------|
| `SeverityFilter` | `VERDICT_MALICIOUS` | Comma-separated GTI verdict levels |
| `ThreatLists` | *(empty)* | Comma-separated GTI threat list categories (empty for all) |
| `LookbackDays` | `5` | Historical lookback period in days for initial sync (max 5) |

> **⚠️ Note:** GuardDuty has a limit of 1,000 domains per threat list file with a maximum of 6 files (6,000 domains total). It is **strongly recommended** to:
> - Specify the `ThreatLists` parameter to filter only the threat categories relevant to your use case, rather than syncing all categories
> - Keep `LookbackDays` to a minimum necessary value to reduce the initial volume of IOCs fetched
> 
> This helps stay within GuardDuty's limits and improves performance.

**Severity Filter Options:** `VERDICT_MALICIOUS`, `VERDICT_SUSPICIOUS`, `VERDICT_UNDETECTED`, `VERDICT_BENIGN`, `VERDICT_UNKNOWN`

### Advanced
| Parameter | Default | Description |
|-----------|---------|-------------|
| `EntityFiles` | `guard_duty/threat-entity-{1-6}.txt` | S3 object keys for domain threat list files (auto-created) |
| `IpFiles` | `guard_duty/threat-ip-{1-6}.txt` | S3 object keys for IP threat list files (auto-created) |

---

## How It Works

1. **EventBridge** triggers Lambda on schedule (default: every hour)
2. **Lambda** retrieves GTI API key from Secrets Manager
3. **Lambda** fetches IOCs from GTI IOC Stream and Threat Lists APIs
4. Valid IOCs are written to **S3** threat list files
5. Updated threat lists are activated in **GuardDuty**
6. Checkpoint is saved to S3 for incremental processing

---

## AWS Resources Created

| Resource | Type | Purpose |
|----------|------|---------|
| `GTISecret` | Secrets Manager Secret | Stores GTI API key |
| `IntegrationBucket` | S3 Bucket | Threat lists, checkpoint, Lambda layer |
| `BucketPolicy` | S3 Bucket Policy | Grants access to Lambda and GuardDuty |
| `LambdaRole` | IAM Role | Execution role for main Lambda |
| `DetectorCustomRole` | IAM Role | Role for detector custom resource |
| `GTILambda` | Lambda Function | Main IOC sync function |
| `LayerZipCreator` | Lambda Function | Builds boto3 layer at deploy time |
| `DetectorCustomFunction` | Lambda Function | Gets/creates GuardDuty detector |
| `ObjectsCustomFunction` | Lambda Function | Creates empty threat files and registers GuardDuty sets |
| `Boto3LambdaLayer` | Lambda Layer | boto3 ≥1.42 for ThreatEntitySet support |
| `ScheduledRule` | EventBridge Rule | Triggers Lambda on schedule |
| `*LogGroup` | CloudWatch Log Groups | 30-day retention for all Lambdas |

---

## GTI Data Sources

### IOC Stream API
- **Endpoint:** GTI IOC Stream API
- **Entity types:** `ip_address`, `domain`
- **Pagination:** Cursor-based with 40 items per page
- **Checkpointing:** Tracks `notification_date` per entity type

### Categorized Threat Lists API
- **Endpoint:** GTI Threat Lists API
- **Granularity:** Hourly buckets (format: `YYYYMMDDHH`)
- **Pagination:** Up to 4,000 IOCs per request
- **Checkpointing:** Tracks last processed hour per category

---

## Lambda Runtime Behavior

### Execution Flow
1. Load checkpoint from S3 (`gti-checkpoint.json`)
2. Validate required environment variables (`ENTITY_FILES`, `IP_FILES`)
3. Initialize GTI client with API key from Secrets Manager
4. Fetch domain IOCs from IOC Stream API
5. Fetch IP IOCs from IOC Stream API
6. Fetch IOCs from configured threat list categories
7. Write invalid IOCs to S3 for review
8. Activate updated GuardDuty threat lists

### Checkpointing
The checkpoint file tracks:
```json
{
  "domain_last_notification_date": 1705766400,
  "ip_address_last_notification_date": 1705766400,
  "threat_lists": {
    "category_name": "2024012011"
  }
}
```

- **IOC Stream:** Unix timestamp of last processed notification
- **Threat Lists:** Hourly timestamp (`YYYYMMDDHH`) per category

### Lookback Logic
- On first run (no checkpoint): fetches from `now - LookbackDays`
- On subsequent runs: fetches from last checkpoint timestamp
- Maximum lookback enforced: 5 days

### IOC Validation
- **IPs:** Must be valid IPv4 address or CIDR notation
- **Domains:** Must match domain regex; URLs rejected; wildcards supported (`*.example.com`)

---

## GuardDuty Constraints

| Constraint | Limit | Implementation |
|------------|-------|----------------|
| Threat lists per type | 6 | Enforced; excess IOCs written to `exceeded_*.txt` |
| File size | 35 MB | Chunked writes |
| IPs per file | 250,000 | `MAX_IP_LINES_PER_FILE` constant |
| Domains per file | 1,000 | `MAX_ENTITY_LINES_PER_FILE` constant |

---

## S3 Bucket Structure

```
s3://<bucket>/
├── guard_duty/
│   ├── threat-ip-1.txt          # IP IOCs (ThreatIntelSet)
│   ├── threat-ip-2.txt
│   ├── ...
│   ├── threat-entity-1.txt      # Domain IOCs (ThreatEntitySet)
│   ├── threat-entity-2.txt
│   └── ...
├── invalid_iocs/
│   ├── invalid_ip_address.txt   # Failed IP validation
│   └── invalid_domain.txt       # Failed domain validation
├── exceeded_ip_address.txt      # Overflow IPs (if >6 files needed)
├── exceeded_domain.txt          # Overflow domains (if >6 files needed)
├── gti-checkpoint.json          # Incremental sync state
└── boto3-layer.zip              # Lambda layer artifact
```

---

## Logging and Monitoring

### CloudWatch Log Groups
All Lambda functions log to CloudWatch with 30-day retention:
- `/aws/lambda/<bucket>-gti-ingest` — Main sync function
- `/aws/lambda/<bucket>-layer-creator` — Layer builder
- `/aws/lambda/DetectorCustomFunction` — Detector lookup
- `/aws/lambda/ObjectsCustomFunction` — File/set creation

### Log Messages
| Prefix | Meaning |
|--------|---------|
| `[INFO]` | Normal operation |
| `[WARN]` | Non-fatal issues (missing files, invalid config) |
| `[ERROR]` | Failures requiring attention |
| `[DEBUG]` | Pagination and fetch details |

### Key Log Patterns
```
[INFO] ===== GTI IOC Sync Lambda Starting =====
[INFO] Using lookback days: 5
[INFO] Fetching IOC Stream (domain) | last_date=1705766400
[DEBUG] Fetched page with 40 items | next_cursor=...
[INFO] Updated S3 file: guard_duty/threat-entity-1.txt | Records: 150 | Size: 0.02 MB
[INFO] Activating threat ENTITY list: s3://bucket/guard_duty/threat-entity-1.txt
[INFO] ✔ IOC Sync Completed Successfully
```

---

## Security Considerations

### Secrets Management
- GTI API key stored in **Secrets Manager** (not environment variables)
- Lambda retrieves secret at runtime via `secretsmanager:GetSecretValue`

### S3 Bucket Security
- Public access blocked (all four settings enabled)
- Bucket policy restricts access to Lambda and GuardDuty services

### IAM Permissions
The Lambda role includes least-privilege policies:
- `secretsmanager:GetSecretValue` — Scoped to GTI secret ARN
- `s3:GetObject`, `s3:PutObject`, `s3:ListBucket` — Scoped to integration bucket
- `guardduty:*ThreatIntelSet`, `guardduty:*ThreatEntitySet` — For threat list management
- `guardduty:ListDetectors` — To discover detector ID

### Network
- Lambda makes outbound HTTPS calls to Google Threat Intelligence APIs
- No VPC configuration required (uses AWS public endpoints)

---

## Troubleshooting

### Lambda Timeout
**Symptom:** `Task timed out after 900.00 seconds`

**Cause:** Large historical fetch on first run or many threat list categories

**Resolution:**
- Reduce `LookbackDays` to 1-3
- Limit categories via `ThreatLists` parameter
- Lambda will resume from checkpoint on next run

### API Key Errors
**Symptom:** `HTTP 401` or `HTTP 403` or `API key not found`

**Resolution:**
- Verify secret exists in Secrets Manager with correct name
- Confirm API key is valid in Google Threat Intelligence console
- Check `SecretKey` parameter matches secret name

### GuardDuty Detector Not Found
**Symptom:** `No GuardDuty detector found in the region`

**Resolution:**
- Enable GuardDuty in the AWS Console
- Verify IAM role has `guardduty:ListDetectors` permission
- Re-run the stack (custom resource will create detector)

### Threat Lists Not Activating
**Symptom:** Lists remain `INACTIVE` in GuardDuty

**Cause:** No new IOCs written during execution

**Resolution:** This is expected behavior. Lists activate only when files are updated.

### Exceeded File Limits
**Symptom:** `Exceeded max GuardDuty ip_address files` in logs

**Cause:** More IOCs than can fit in 6 files

**Resolution:**
- Check `exceeded_ip_address.txt` or `exceeded_domain.txt` in S3
- Tighten `SeverityFilter` to reduce volume
- Limit threat list categories

### Invalid IOCs
**Symptom:** Some IOCs not appearing in threat lists

**Cause:** Failed validation (non-IPv4, URLs, malformed domains)

**Resolution:**
- Review `invalid_iocs/invalid_ip_address.txt` and `invalid_iocs/invalid_domain.txt`
- This is expected behavior; invalid IOCs are logged and skipped

### CloudFormation Failures
**Symptom:** Stack stuck in `CREATE_FAILED`

**Resolution:**
1. Check **CloudFormation → Events** for failing resource
2. Review corresponding Lambda logs
3. Common causes: IAM permissions, duplicate bucket/secret names

---

## Stack Outputs

| Output | Description |
|--------|-------------|
| `S3Bucket` | Integration bucket name |
| `SecretName` | Secrets Manager secret name |
| `LambdaFunction` | Main Lambda function ARN |
| `DetectorId` | GuardDuty detector ID |
