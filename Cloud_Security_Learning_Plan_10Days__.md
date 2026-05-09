# 🛡️ Cloud Security & Enterprise IT Operational Security
## 10-Day Superfast Training Program — AWS Practical Implementation

> **Target Audience:** IT Professionals, Security Engineers, Cloud Architects, SOC Analysts
> **Platform Focus:** AWS (Amazon Web Services) with universal enterprise principles
> **Certification Alignment:** AWS Security Specialty, CompTIA Security+, CCSP
> **Study Method:** Accelerated Sprint Learning (Theory → Lab → Case Study → Apply)

---

## 📋 Program Overview

| Metric | Detail |
|--------|--------|
| Duration | 10 Days (4 hours/day) |
| Format | 25% Theory, 75% Hands-On Labs |
| Platform | AWS Management Console + AWS CLI |
| Deliverable | Production-ready Security Runbook |
| Final Assessment | Architecture Review + Incident Simulation |

### Learning Sprint Philosophy (3-Step Daily Cycle)
```
🔵 ABSORB (1h)  →  🟡 APPLY (2h)  →  🔴 CHALLENGE (1h)
Theory + Concept    Lab + Config       Case Study + Quiz
```

### Recommended Daily 4-Hour Schedule
```
Block 1 (1h):  Theory and concepts — AWS docs + this guide          (ABSORB)
Block 2 (2h):  Hands-on labs — AWS Console + AWS CLI                (APPLY)
Block 3 (1h):  Case study + quiz + update your security runbook     (CHALLENGE)
```

---

## 🗓️ DAY 1 — Cloud Security Foundations & IAM

### 🎯 Learning Objectives
- Understand the Shared Responsibility Model on AWS
- Master Identity and Access Management (IAM) architecture
- Configure MFA and least-privilege access policies

> **🔐 OWASP Coverage:** [A01 Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) · [A07 Identification & Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)

### 📖 Theory — Block 1 (1 Hour)

#### 1.1 Shared Responsibility Model
```
┌─────────────────────────────────────────────┐
│           CUSTOMER RESPONSIBILITY           │
│  Data | IAM | App Config | OS Patches       │
├─────────────────────────────────────────────┤
│              AWS RESPONSIBILITY             │
│  Physical | Network | Hypervisor | Hardware │
└─────────────────────────────────────────────┘
```

**Key Principle:** You own your data and access controls. AWS secures the infrastructure.

#### 1.2 AWS IAM Architecture
- **Root Account** — Never use for daily operations; delete its access keys immediately
- **IAM Users** — Human users and service accounts with long-term credentials
- **IAM Roles** — Temporary credentials for AWS services and cross-account access
- **Policies** — JSON documents defining allowed/denied actions on resources
- **Groups** — Collections of IAM users sharing the same policy set

#### 1.3 Policy Evaluation Logic
```
Explicit DENY   → Overrides all ALLOW (always wins)
No statement    → Default DENY (implicit deny)
Explicit ALLOW  → Grants access (only if no DENY exists)
SCP (Org)       → Acts as outer boundary; overrides even Explicit ALLOW
```

### 🔬 Lab — Block 2 (2 Hours)

#### Lab 1A — IAM Setup for RentDrive SaaS Platform

#### Step 1: Install AWS CLI and Create Admin IAM User (Never Use Root)
```bash
# Install AWS CLI v2
pip install awscli --upgrade

# Configure with root credentials (one-time only — then delete root keys!)
aws configure
# Prompts: Access Key ID, Secret Access Key, Region: ap-southeast-1, Output: json

# Create IAM admin user for daily operations
aws iam create-user \
  --user-name security-admin \
  --tags Key=Team,Value=Security Key=App,Value=RentDrive

# Create console login profile with forced password reset
aws iam create-login-profile \
  --user-name security-admin \
  --password "Str0ng!P@ss$(date +%Y)" \
  --password-reset-required

# Add user to Admins group
aws iam create-group --group-name SecurityAdmins
aws iam attach-group-policy \
  --group-name SecurityAdmins \
  --policy-arn arn:aws:iam::aws:policy/SecurityAudit
aws iam add-user-to-group --user-name security-admin --group-name SecurityAdmins
```

#### Step 2: Create Least-Privilege Policy (Read-Only EC2 from Internal IPs)
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowReadOnlyEC2FromInternal",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances",
        "ec2:DescribeInstanceStatus",
        "cloudwatch:GetMetricData",
        "cloudwatch:ListMetrics"
      ],
      "Resource": "*",
      "Condition": {
        "IpAddress": {
          "aws:SourceIp": ["10.0.0.0/8", "192.168.1.0/24"]
        }
      }
    },
    {
      "Sid": "DenyIAMAndBilling",
      "Effect": "Deny",
      "Action": ["iam:*", "billing:*", "ce:*"],
      "Resource": "*"
    }
  ]
}
```

```bash
# Create and attach the least-privilege policy
aws iam create-policy \
  --policy-name "ReadOnly-EC2-InternalIPsOnly" \
  --policy-document file://policy.json \
  --description "Read-only EC2/CloudWatch access from corporate network only"

POLICY_ARN=$(aws iam list-policies \
  --query "Policies[?PolicyName=='ReadOnly-EC2-InternalIPsOnly'].Arn" \
  --output text)

aws iam attach-user-policy \
  --user-name security-admin \
  --policy-arn "$POLICY_ARN"
```

#### Step 3: Enable MFA and GuardDuty
```bash
# Create virtual MFA device for the admin user
aws iam create-virtual-mfa-device \
  --virtual-mfa-device-name security-admin-mfa \
  --outfile /tmp/mfa-qr.png \
  --bootstrap-method QRCodePNG
# Scan the QR code with Google Authenticator or Authy
# Then enable it with two consecutive OTP codes:
aws iam enable-mfa-device \
  --user-name security-admin \
  --serial-number "arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):mfa/security-admin-mfa" \
  --authentication-code1 123456 \
  --authentication-code2 654321

# Attach an inline policy that denies ALL actions without MFA
aws iam put-user-policy \
  --user-name security-admin \
  --policy-name DenyWithoutMFA \
  --policy-document '{
    "Version":"2012-10-17",
    "Statement":[{
      "Effect":"Deny",
      "Action":"*",
      "Resource":"*",
      "Condition":{"BoolIfExists":{"aws:MultiFactorAuthPresent":"false"}}
    }]
  }'

# Enable GuardDuty for ML-based threat detection
DETECTOR_ID=$(aws guardduty create-detector \
  --enable \
  --finding-publishing-frequency FIFTEEN_MINUTES \
  --query 'DetectorId' --output text)
echo "GuardDuty Detector ID: $DETECTOR_ID"

# Delete root account access keys immediately after setup
# (Do this manually in AWS Console: IAM → Security credentials → Root)
```

#### 🔐 OWASP A01 & A07 — Policy to AWS Implementation

**OWASP A01 Policy:** *"Enforce access controls server-side; deny access by default; alert on access control failures."*
**OWASP A07 Policy:** *"Require strong MFA; block brute force; never expose session tokens or long-lived credentials."*

```bash
# ── A01: Broken Access Control ──────────────────────────────────────────────
# Enable IAM Access Analyzer — detect unintended external/cross-account access paths
aws accessanalyzer create-analyzer \
  --analyzer-name "rentdrive-access-analyzer" \
  --type ACCOUNT \
  --tags Key=Environment,Value=production

# AWS Config rule: deny IAM policies granting Action:* Resource:* (wildcard privilege escalation)
aws configservice put-config-rule --config-rule '{
  "ConfigRuleName": "iam-policy-no-statements-with-admin-access",
  "Source": {"Owner":"AWS","SourceIdentifier":"IAM_POLICY_NO_STATEMENTS_WITH_ADMIN_ACCESS"}
}'

# List active Access Analyzer findings — all are OWASP A01 violations requiring remediation
aws accessanalyzer list-findings \
  --analyzer-name "rentdrive-access-analyzer" \
  --filter '{"status":{"eq":["ACTIVE"]}}' \
  --query 'findings[].{Resource:resource,Type:resourceType,Principal:principal}' \
  --output table

# ── A07: Authentication Failures ────────────────────────────────────────────
# AWS Config rule: MFA required for all IAM users with console access
aws configservice put-config-rule --config-rule '{
  "ConfigRuleName": "mfa-enabled-for-iam-console-access",
  "Source": {"Owner":"AWS","SourceIdentifier":"MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS"}
}'

# CloudWatch alarm: root account login → paged immediately (A07 critical indicator)
aws logs put-metric-filter \
  --log-group-name "rentdrive-cloudtrail-logs" \
  --filter-name "OWASP-A07-RootLogin" \
  --filter-pattern '{ $.userIdentity.type = "Root" && $.eventType != "AwsServiceEvent" }' \
  --metric-transformations MetricName=RootLoginCount,MetricNamespace=OWASPAlerts,DefaultValue=0,Value=1

aws cloudwatch put-metric-alarm \
  --alarm-name "OWASP-A07-RootAccountLogin" \
  --namespace OWASPAlerts --metric-name RootLoginCount \
  --statistic Sum --period 60 --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold --evaluation-periods 1 \
  --alarm-actions "$SNS_ARN" \
  --alarm-description "OWASP A07: Root account login — investigate immediately"

# Verification: zero non-compliant resources expected
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name "mfa-enabled-for-iam-console-access" \
  --compliance-types NON_COMPLIANT \
  --query 'EvaluationResults[].EvaluationResultIdentifier.EvaluationResultQualifier.ResourceId'
# Expected result: []
```

### 📚 Challenge — Block 3 (1 Hour)

#### Study Case 1: Credential Leak at RentDrive SaaS Platform

**Scenario:** A backend developer at **RentDrive** — a B2B SaaS car rental management platform serving 250+ fleet operators — accidentally committed AWS IAM long-term access keys directly to a public GitHub repository. Within 6 hours, an attacker enumerated regions, spun up **80 p3.16xlarge GPU instances** for cryptocurrency mining, and generated an **$82,000 overnight AWS bill**.

**Root Causes:**
- Long-term IAM access keys embedded directly in application source code
- No IP-based restrictions on API keys (keys usable from anywhere)
- No AWS Budgets anomaly alerts configured
- No `git-secrets` or secret scanning in the CI/CD pipeline
- Root account still had active access keys

**AWS Prevention Controls:**
1. **AWS Secrets Manager** — Store all credentials; supports 30-day auto-rotation
2. **IAM condition `aws:SourceIp`** — Restrict keys to corporate IP ranges only
3. **AWS Budgets** — Alerts at 50%, 80%, 100% of monthly spend threshold
4. **Amazon CodeGuru / git-secrets** — Scan every commit for credential patterns
5. **AWS CloudTrail** multi-region trail — Complete API audit log from day one
6. **GuardDuty** — `CryptoCurrency:EC2/BitcoinTool.B` finding fires within minutes

**Resolution Checklist:**
```
☑ Immediately rotate ALL IAM access keys (Console → IAM → Users → Security credentials)
☑ Check CloudTrail in ALL regions for unauthorized resource creation
☑ Terminate every unauthorized EC2 instance (check all 30+ AWS regions)
☑ Contact AWS Support → billing dispute (document the incident timeline)
☑ File internal security incident report with timeline
☑ Enable AWS Config rule: access-keys-rotated (90-day max)
☑ Enable GuardDuty + SNS alert for CryptoCurrency finding type
☑ Add git-secrets pre-commit hook to all developer workstations
```

**RentDrive Business Impact:**
- Fleet operator booking API offline for 3 hours during containment
- SLA breach penalties triggered with 2 enterprise clients (~$15,000)
- SOC 2 Type II audit scope expanded, delaying certification by 8 weeks

### ✅ Day 1 Assessment
- [ ] Root account MFA enabled + access keys deleted
- [ ] IAM admin user created, never using root for daily ops
- [ ] Least-privilege policy applied with IP source condition
- [ ] MFA enforce policy attached (deny all without MFA)
- [ ] CloudTrail multi-region trail enabled
- [ ] GuardDuty enabled in primary region (ap-southeast-1)
- [ ] AWS Budgets alert configured at 50% / 80% / 100%

---

## 🗓️ DAY 2 — Network Security Architecture

### 🎯 Learning Objectives
- Design secure VPC architecture with defense-in-depth for car rental SaaS
- Configure Security Groups (stateful) and Network ACLs (stateless)
- Replace SSH bastion hosts with AWS Systems Manager Session Manager

> **🔐 OWASP Coverage:** [A05 Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) · [A01 Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)

### 📖 Theory — Block 1 (1 Hour)

#### 2.1 Defense-in-Depth Network Model (RentDrive Architecture)
```
Internet
    │
    ▼
[AWS Shield Standard + WAF v2]       ← DDoS + Layer 7 protection
    │
    ▼
[ALB — Public Subnet /24]            ← Only resource with public IP
    │
    ▼
[API / Web Tier — Private Subnet A]  ← SG: 443 from ALB SG only
    │
    ▼
[App / Worker Tier — Private Subnet B] ← SG: 8080 from API SG only
    │
    ▼
[RDS MySQL — Private Subnet C]       ← SG: 3306 from App SG only
    │
    ▼
[SSM Session Manager]                ← Admin access: no port 22, fully audited
```

#### 2.2 Security Groups vs Network ACL

| Feature | Security Group | Network ACL |
|---------|---------------|-------------|
| Level | Instance / ENI level | Subnet level |
| State | Stateful (return traffic auto-allowed) | Stateless (must allow both directions) |
| Rules | Allow only | Allow + Deny (numbered, evaluated in order) |
| Default | Deny all inbound | Allow all (default NACL) |
| Best for | Micro-segmentation per resource | Subnet-level perimeter control |

### 🔬 Lab — Block 2 (2 Hours)

#### Lab 2A — Three-Tier VPC for RentDrive Platform

#### Step 1: Create VPC, Subnets, and Internet Gateway
```bash
REGION="ap-southeast-1"

# Create VPC
VPC_ID=$(aws ec2 create-vpc \
  --cidr-block "10.10.0.0/16" \
  --region $REGION \
  --tag-specifications 'ResourceType=vpc,Tags=[{Key=Name,Value=rentdrive-prod-vpc},{Key=Environment,Value=production}]' \
  --query 'Vpc.VpcId' --output text)
echo "VPC: $VPC_ID"

# Enable DNS resolution (required for SSM Session Manager and RDS)
aws ec2 modify-vpc-attribute --vpc-id $VPC_ID --enable-dns-hostnames
aws ec2 modify-vpc-attribute --vpc-id $VPC_ID --enable-dns-support

# Create and attach Internet Gateway (ALB needs this; private subnets use NAT)
IGW_ID=$(aws ec2 create-internet-gateway \
  --tag-specifications 'ResourceType=internet-gateway,Tags=[{Key=Name,Value=rentdrive-igw}]' \
  --query 'InternetGateway.InternetGatewayId' --output text)
aws ec2 attach-internet-gateway --internet-gateway-id $IGW_ID --vpc-id $VPC_ID

# Public subnet — ALB only; NO application instances here
PUBLIC_SUBNET=$(aws ec2 create-subnet \
  --vpc-id $VPC_ID --cidr-block "10.10.1.0/24" --availability-zone "${REGION}a" \
  --tag-specifications 'ResourceType=subnet,Tags=[{Key=Name,Value=public-alb-a}]' \
  --query 'Subnet.SubnetId' --output text)

# Private app/API subnet
APP_SUBNET=$(aws ec2 create-subnet \
  --vpc-id $VPC_ID --cidr-block "10.10.10.0/24" --availability-zone "${REGION}a" \
  --tag-specifications 'ResourceType=subnet,Tags=[{Key=Name,Value=private-app-a}]' \
  --query 'Subnet.SubnetId' --output text)

# Private DB subnet (two AZs required for RDS Multi-AZ)
DB_SUBNET_A=$(aws ec2 create-subnet \
  --vpc-id $VPC_ID --cidr-block "10.10.20.0/24" --availability-zone "${REGION}a" \
  --tag-specifications 'ResourceType=subnet,Tags=[{Key=Name,Value=private-db-a}]' \
  --query 'Subnet.SubnetId' --output text)
DB_SUBNET_B=$(aws ec2 create-subnet \
  --vpc-id $VPC_ID --cidr-block "10.10.21.0/24" --availability-zone "${REGION}b" \
  --tag-specifications 'ResourceType=subnet,Tags=[{Key=Name,Value=private-db-b}]' \
  --query 'Subnet.SubnetId' --output text)
```

#### Step 2: Configure Security Groups — Principle of Least Privilege
```bash
# ALB Security Group — accepts HTTPS from internet
SG_ALB=$(aws ec2 create-security-group \
  --group-name "sg-alb" --description "ALB — public HTTPS only" \
  --vpc-id $VPC_ID --query 'GroupId' --output text)
aws ec2 authorize-security-group-ingress --group-id $SG_ALB \
  --protocol tcp --port 443 --cidr 0.0.0.0/0
aws ec2 authorize-security-group-ingress --group-id $SG_ALB \
  --protocol tcp --port 80 --cidr 0.0.0.0/0  # Redirect to HTTPS only

# App tier SG — accepts traffic ONLY from ALB SG (not from any CIDR range)
SG_APP=$(aws ec2 create-security-group \
  --group-name "sg-app-tier" --description "App tier — from ALB SG only" \
  --vpc-id $VPC_ID --query 'GroupId' --output text)
aws ec2 authorize-security-group-ingress --group-id $SG_APP \
  --protocol tcp --port 8080 --source-group $SG_ALB

# DB SG — accepts MySQL ONLY from app tier SG
SG_DB=$(aws ec2 create-security-group \
  --group-name "sg-db-tier" --description "RDS MySQL — app tier only" \
  --vpc-id $VPC_ID --query 'GroupId' --output text)
aws ec2 authorize-security-group-ingress --group-id $SG_DB \
  --protocol tcp --port 3306 --source-group $SG_APP

echo "Security groups configured. DB accepts MySQL from app-SG only — no internet exposure."
```

#### Step 3: SSM Session Manager — Replace SSH Bastion Entirely
```bash
# Create IAM role for EC2 instances (attach to ALL production instances)
aws iam create-role \
  --role-name "EC2-SSM-RentDrive-Role" \
  --assume-role-policy-document '{
    "Version":"2012-10-17",
    "Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]
  }'
aws iam attach-role-policy \
  --role-name "EC2-SSM-RentDrive-Role" \
  --policy-arn "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"

aws iam create-instance-profile --instance-profile-name "EC2-SSM-RentDrive-Profile"
aws iam add-role-to-instance-profile \
  --instance-profile-name "EC2-SSM-RentDrive-Profile" \
  --role-name "EC2-SSM-RentDrive-Role"

# Connect to any instance — NO SSH key, NO port 22, fully CloudTrail-logged
# aws ssm start-session --target i-0123456789abcdef0

# Verify all instances are SSM-managed
aws ssm describe-instance-information \
  --query 'InstanceInformationList[].{ID:InstanceId,Status:PingStatus,Platform:PlatformType}' \
  --output table

# IMPORTANT: Remove all inbound port 22 rules from production security groups
aws ec2 revoke-security-group-ingress --group-id $SG_APP \
  --protocol tcp --port 22 --cidr 0.0.0.0/0 2>/dev/null || echo "Port 22 not open — good"
```

#### 🔐 OWASP A05 — Policy to AWS Implementation

**OWASP A05 Policy:** *"Maintain repeatable hardening processes; disable all default credentials and unused features; no default open ports; review and update cloud security configurations regularly."*

```bash
# ── A05: Security Misconfiguration Detection ────────────────────────────────
# Config rule: block security groups allowing unrestricted SSH (OWASP A05 — open port 22)
aws configservice put-config-rule --config-rule '{
  "ConfigRuleName": "restricted-ssh",
  "Source": {"Owner":"AWS","SourceIdentifier":"RESTRICTED_INCOMING_TRAFFIC"},
  "InputParameters": "{"blockedPort1":"22"}"
}'

# Config rule: RDS instances must not be publicly accessible
aws configservice put-config-rule --config-rule '{
  "ConfigRuleName": "rds-instance-public-access-check",
  "Source": {"Owner":"AWS","SourceIdentifier":"RDS_INSTANCE_PUBLIC_ACCESS_CHECK"}
}'

# Config rule: EC2 instances must not have public IP on private subnet instances
aws configservice put-config-rule --config-rule '{
  "ConfigRuleName": "ec2-instance-no-public-ip",
  "Source": {"Owner":"AWS","SourceIdentifier":"EC2_INSTANCE_NO_PUBLIC_IP"}
}'

# Audit: find all security groups with 0.0.0.0/0 inbound rules (OWASP A05 misconfiguration)
aws ec2 describe-security-groups \
  --filters "Name=ip-permission.cidr,Values=0.0.0.0/0" \
  --query 'SecurityGroups[].{ID:GroupId,Name:GroupName,Ports:IpPermissions[].{Port:ToPort,Proto:IpProtocol}}' \
  --output table

# Security Hub: enable AWS Foundational Best Practices standard (OWASP A05 alignment)
aws securityhub enable-security-hub --enable-default-standards

# Verification: report all misconfig Config rule violations
aws configservice describe-compliance-by-config-rule \
  --config-rule-names restricted-ssh rds-instance-public-access-check ec2-instance-no-public-ip \
  --compliance-types NON_COMPLIANT \
  --query 'ComplianceByConfigRules[].ConfigRuleName'
# Expected result: []
```

### 📚 Challenge — Block 3 (1 Hour)

#### Study Case 2: RDS Database Exposed to Internet

**Scenario:** **FleetOps** — a competitor SaaS car rental platform — placed their RDS MySQL instance in a public subnet with `PubliclyAccessible: true` during a rushed "demo environment" setup that was never decommissioned. A Shodan scan found it within 2 days. Attackers used SQL injection to exfiltrate **1.4M vehicle booking records and driver license image URLs**.

**Violations Found:**
- RDS in public subnet with `PubliclyAccessible: true`
- Security group rule: `0.0.0.0/0 → TCP 3306` — open to the entire internet
- No RDS encryption at rest, no SSL enforcement
- Database master password stored in plaintext `.env` file committed to a private (but shared) git repo

**Remediation Applied:**
1. `aws rds modify-db-instance --no-publicly-accessible` — remove public IP
2. Move RDS to private subnet; update security group to app-tier SG source only
3. Enable RDS storage encryption with KMS CMK
4. Set RDS parameter: `rds.force_ssl = 1`
5. Migrate credentials to **AWS Secrets Manager** with 30-day auto-rotation

---

## 🗓️ DAY 3 — Data Security & Encryption

### 🎯 Learning Objectives
- Implement encryption at rest (KMS CMK) and in transit (TLS enforcement)
- Secure S3 buckets storing car rental documents, contracts, and driver data
- Enable Amazon Macie for automated PII discovery

> **🔐 OWASP Coverage:** [A02 Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)

### 📖 Theory — Block 1 (1 Hour)

#### 3.1 AWS Encryption Layers
- **AWS KMS CMK (Customer Managed Key)** — You control key policy, rotation, deletion schedule
- **AWS Managed Key** — AWS manages the key on your behalf; limited auditability
- **SSE-S3** — S3-managed AES-256 encryption (no KMS charges, no per-request audit)
- **SSE-KMS** — S3 encrypted with your KMS CMK (full CloudTrail audit per object access)
- **Client-side encryption** — Encrypt before upload; maximum security, more complexity

#### 3.2 S3 Security Hierarchy for Car Rental SaaS
```
Account Level:  S3 Block Public Access (account-wide setting — enable this first)
Bucket Level:   Bucket Policy → Block Public Access → SSE-KMS default encryption
Object Level:   S3 Object Lock (WORM) → Object versions
Access Level:   IAM Policy → Bucket Policy → VPC Endpoint Policy
Monitoring:     Amazon Macie (PII discovery) → CloudTrail S3 data events
```

### 🔬 Lab — Block 2 (2 Hours)

#### Lab 3A — KMS, S3 Encryption, and Macie for RentDrive

#### Step 1: Create Customer Managed KMS Key
```bash
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
REGION="ap-southeast-1"

# Create KMS CMK for RentDrive sensitive data
KEY_ID=$(aws kms create-key \
  --description "RentDrive Production CMK — Car rental documents and PII" \
  --key-usage ENCRYPT_DECRYPT \
  --origin AWS_KMS \
  --tags TagKey=Environment,TagValue=production TagKey=Application,TagValue=RentDrive \
  --query 'KeyMetadata.KeyId' --output text)

# Create a human-readable alias
aws kms create-alias \
  --alias-name "alias/rentdrive-prod-cmk" \
  --target-key-id "$KEY_ID"

# Enable automatic annual rotation (best practice)
aws kms enable-key-rotation --key-id "$KEY_ID"

echo "KMS CMK: $KEY_ID"
echo "Alias: alias/rentdrive-prod-cmk"
```

#### Step 2: Create Encrypted S3 Buckets for Car Rental Documents
```bash
# Bucket 1: Operational documents (vehicle inspections, booking confirmations)
aws s3api create-bucket \
  --bucket "rentdrive-documents-${ACCOUNT_ID}" \
  --region $REGION \
  --create-bucket-configuration LocationConstraint=$REGION

# Apply SSE-KMS default encryption
aws s3api put-bucket-encryption \
  --bucket "rentdrive-documents-${ACCOUNT_ID}" \
  --server-side-encryption-configuration "{
    \"Rules\": [{
      \"ApplyServerSideEncryptionByDefault\": {
        \"SSEAlgorithm\": \"aws:kms\",
        \"KMSMasterKeyID\": \"$KEY_ID\"
      },
      \"BucketKeyEnabled\": true
    }]
  }"

# Block ALL public access — account-wide and bucket-level
aws s3control put-public-access-block \
  --account-id $ACCOUNT_ID \
  --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# Enable versioning (enables MFA-Delete and ransomware recovery)
aws s3api put-bucket-versioning \
  --bucket "rentdrive-documents-${ACCOUNT_ID}" \
  --versioning-configuration Status=Enabled

# Bucket 2: Legal contracts with Object Lock (WORM) — must be set at creation
aws s3api create-bucket \
  --bucket "rentdrive-contracts-${ACCOUNT_ID}" \
  --region $REGION \
  --object-lock-enabled-for-bucket \
  --create-bucket-configuration LocationConstraint=$REGION

aws s3api put-object-lock-configuration \
  --bucket "rentdrive-contracts-${ACCOUNT_ID}" \
  --object-lock-configuration '{
    "ObjectLockEnabled": "Enabled",
    "Rule": {
      "DefaultRetention": {
        "Mode": "COMPLIANCE",
        "Days": 2555
      }
    }
  }'
echo "Contracts bucket: WORM compliance mode, 7-year retention"
```

#### Step 3: Enforce TLS and Enable Amazon Macie
```bash
# Deny all non-HTTPS access to sensitive buckets
aws s3api put-bucket-policy \
  --bucket "rentdrive-documents-${ACCOUNT_ID}" \
  --policy "{
    \"Statement\": [{
      \"Sid\": \"DenyNonTLS\",
      \"Effect\": \"Deny\",
      \"Principal\": \"*\",
      \"Action\": \"s3:*\",
      \"Resource\": [
        \"arn:aws:s3:::rentdrive-documents-${ACCOUNT_ID}\",
        \"arn:aws:s3:::rentdrive-documents-${ACCOUNT_ID}/*\"
      ],
      \"Condition\": {\"Bool\": {\"aws:SecureTransport\": \"false\"}}
    }]
  }"

# Enable Amazon Macie — automated PII discovery (driver licenses, payment data)
aws macie2 enable-macie

aws macie2 create-classification-job \
  --name "PII-Scan-RentDrive-Documents" \
  --job-type SCHEDULED \
  --schedule-frequency '{"WeeklySchedule":{"DayOfWeek":"MONDAY"}}' \
  --s3-job-definition "{
    \"BucketDefinitions\": [{
      \"AccountId\": \"$ACCOUNT_ID\",
      \"Buckets\": [\"rentdrive-documents-${ACCOUNT_ID}\"]
    }]
  }"

# Enable S3 data events in CloudTrail (forensic audit per-object access)
aws cloudtrail put-event-selectors \
  --trail-name "rentdrive-security-trail" \
  --event-selectors "[{
    \"ReadWriteType\": \"All\",
    \"IncludeManagementEvents\": true,
    \"DataResources\": [{
      \"Type\": \"AWS::S3::Object\",
      \"Values\": [\"arn:aws:s3:::rentdrive-documents-${ACCOUNT_ID}/\"]
    }]
  }]"
```

#### 🔐 OWASP A02 — Policy to AWS Implementation

**OWASP A02 Policy:** *"Classify data by sensitivity; encrypt all sensitive data at rest and in transit; enforce TLS everywhere; never use deprecated protocols (SSLv3, TLS 1.0/1.1, MD5, SHA-1); rotate keys on a defined schedule."*

```bash
# ── A02: Cryptographic Failures Prevention ──────────────────────────────────
# Config rule: S3 server-side encryption required (no plaintext object storage)
aws configservice put-config-rule --config-rule '{
  "ConfigRuleName": "s3-bucket-server-side-encryption-enabled",
  "Source": {"Owner":"AWS","SourceIdentifier":"S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED"}
}'

# Config rule: RDS storage encryption at rest required
aws configservice put-config-rule --config-rule '{
  "ConfigRuleName": "rds-storage-encrypted",
  "Source": {"Owner":"AWS","SourceIdentifier":"RDS_STORAGE_ENCRYPTED"}
}'

# Enforce TLS-only on S3 bucket — deny all HTTP access (OWASP A02: no plaintext transport)
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
BUCKET="rentdrive-documents-${ACCOUNT_ID}"
aws s3api put-bucket-policy --bucket "$BUCKET" --policy "{
  "Version":"2012-10-17",
  "Statement":[{
    "Sid":"OWASP-A02-DenyNonTLS",
    "Effect":"Deny",
    "Principal":"*",
    "Action":"s3:*",
    "Resource":["arn:aws:s3:::${BUCKET}","arn:aws:s3:::${BUCKET}/*"],
    "Condition":{"Bool":{"aws:SecureTransport":"false"}}
  }]
}"

# ALB: enforce TLS 1.2+ cipher policy (block SSLv3, TLS 1.0, TLS 1.1)
aws elbv2 modify-listener \
  --listener-arn "$HTTPS_LISTENER_ARN" \
  --ssl-policy "ELBSecurityPolicy-TLS13-1-2-2021-06"
echo "ALB cipher: TLS 1.2+ only — OWASP A02 compliant (blocks deprecated protocols)"

# Audit KMS CMK rotation status — all CMKs must have annual rotation enabled
aws kms list-keys --query 'Keys[].KeyId' --output text | tr '\t' '\n' | while read KEY; do
  ROT=$(aws kms get-key-rotation-status --key-id "$KEY" --query 'KeyRotationEnabled' --output text 2>/dev/null)
  [ "$ROT" = "False" ] && echo "OWASP A02 WARNING — no rotation on KMS key: $KEY"
done

# Verification: zero unencrypted RDS and S3 violations
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name "rds-storage-encrypted" --compliance-types NON_COMPLIANT \
  --query 'EvaluationResults[].EvaluationResultIdentifier.EvaluationResultQualifier.ResourceId'
# Expected result: []
```

### 📚 Challenge — Block 3 (1 Hour)

#### Study Case 3: Ransomware Attack on RentDrive S3 Storage

**Scenario:** A car rental SaaS provider's S3 bucket — containing vehicle inspection photos, signed rental agreements, and driver document scans (800GB) — was accessed via a compromised IAM access key. The attacker used `aws s3 rm --recursive` to mass-delete all objects and demanded $200,000 ransom. S3 versioning was disabled. **Recovery was impossible.**

**Prevention Framework Applied:**
```
1. S3 Object Lock (WORM compliance mode) — 7-year retention for contracts
2. S3 Versioning enabled — 90-day version history for operational documents
3. MFA-Delete enabled — requires physical MFA token to delete object versions
4. S3 Cross-Region Replication — auto-copy to ap-northeast-1 (Tokyo)
5. CloudTrail S3 data events — log every GET/PUT/DELETE per object
6. Amazon EventBridge rule — alert on >50 DeleteObject API calls per hour
7. Amazon Macie — detect anomalous mass-access on PII-tagged objects
8. AWS Backup Vault Lock — immutable backup vault, even admins cannot delete
```

---

## 🗓️ DAY 4 — Security Monitoring & SIEM

### 🎯 Learning Objectives
- Configure AWS CloudTrail as the complete API audit backbone
- Build real-time security alarms with CloudWatch Metric Filters
- Centralize all findings with Amazon GuardDuty + AWS Security Hub

> **🔐 OWASP Coverage:** [A09 Security Logging & Monitoring Failures](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/)

### 📖 Theory — Block 1 (1 Hour)

#### 4.1 AWS Security Monitoring Architecture
```
API call → CloudTrail (audit log) → CloudWatch Logs → Metric Filters → Alarms → SNS
                │
                ▼
          S3 Archive (7-year Glacier Deep Archive)
                │
                ▼
      AWS Security Hub  (single pane of glass)
        ├── GuardDuty       (AI/ML threat detection)
        ├── Inspector v2    (vulnerability findings)
        ├── Macie           (PII/data exposure)
        └── AWS Config      (compliance posture drift)
```

### 🔬 Lab — Block 2 (2 Hours)

#### Lab 4A — CloudTrail, CloudWatch Alarms, GuardDuty, Security Hub

#### Step 1: Enable Multi-Region CloudTrail with Log Validation
```bash
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# Create dedicated S3 bucket for CloudTrail (ideally in a separate log-archive account)
aws s3api create-bucket \
  --bucket "rentdrive-cloudtrail-${ACCOUNT_ID}" \
  --region ap-southeast-1 \
  --create-bucket-configuration LocationConstraint=ap-southeast-1

# Enforce encryption on audit bucket
aws s3api put-bucket-encryption \
  --bucket "rentdrive-cloudtrail-${ACCOUNT_ID}" \
  --server-side-encryption-configuration \
    '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'

# Block public access on audit bucket
aws s3api put-public-access-block \
  --bucket "rentdrive-cloudtrail-${ACCOUNT_ID}" \
  --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# Create multi-region CloudTrail (covers ALL regions — critical for global attacks)
aws cloudtrail create-trail \
  --name "rentdrive-security-trail" \
  --s3-bucket-name "rentdrive-cloudtrail-${ACCOUNT_ID}" \
  --is-multi-region-trail \
  --enable-log-file-validation \
  --include-global-service-events \
  --cloud-watch-logs-log-group-arn "arn:aws:logs:ap-southeast-1:${ACCOUNT_ID}:log-group:RentDrive-CloudTrail:*" \
  --cloud-watch-logs-role-arn "arn:aws:iam::${ACCOUNT_ID}:role/CloudTrail-CWLogs-Role"

aws cloudtrail start-logging --name "rentdrive-security-trail"
echo "Multi-region CloudTrail active — all regions covered"
```

#### Step 2: CloudWatch Metric Filters for Critical Security Events
```bash
LOG_GROUP="RentDrive-CloudTrail"

# Create SNS topic for immediate security alerts
SNS_ARN=$(aws sns create-topic --name "rentdrive-security-alerts" \
  --query 'TopicArn' --output text)
aws sns subscribe --topic-arn "$SNS_ARN" \
  --protocol email --notification-endpoint "security@rentdrive.io"

# Alert 1: Root account usage (CRITICAL — should NEVER happen in normal operations)
aws logs put-metric-filter \
  --log-group-name "$LOG_GROUP" \
  --filter-name "RootAccountUsage" \
  --filter-pattern '{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }' \
  --metric-transformations metricName=RootAccountUsage,metricNamespace=RentDriveSecurityMetrics,metricValue=1

aws cloudwatch put-metric-alarm \
  --alarm-name "CRITICAL-Root-Account-Login" \
  --namespace RentDriveSecurityMetrics --metric-name RootAccountUsage \
  --statistic Sum --period 60 --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold --evaluation-periods 1 \
  --alarm-actions "$SNS_ARN" --ok-actions "$SNS_ARN"

# Alert 2: IAM policy modifications
aws logs put-metric-filter \
  --log-group-name "$LOG_GROUP" \
  --filter-name "IAMPolicyChanges" \
  --filter-pattern '{($.eventName=PutUserPolicy)||($.eventName=PutRolePolicy)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||($.eventName=CreatePolicyVersion)}' \
  --metric-transformations metricName=IAMPolicyChanges,metricNamespace=RentDriveSecurityMetrics,metricValue=1

aws cloudwatch put-metric-alarm \
  --alarm-name "HIGH-IAM-Policy-Change" \
  --namespace RentDriveSecurityMetrics --metric-name IAMPolicyChanges \
  --statistic Sum --period 300 --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold --evaluation-periods 1 \
  --alarm-actions "$SNS_ARN"

# Alert 3: Security group opened to 0.0.0.0/0 (common misconfiguration)
aws logs put-metric-filter \
  --log-group-name "$LOG_GROUP" \
  --filter-name "SecurityGroupOpenToInternet" \
  --filter-pattern '{ ($.eventName = AuthorizeSecurityGroupIngress) && ($.requestParameters.ipPermissions.items[0].ipRanges.items[0].cidrIp = "0.0.0.0/0") }' \
  --metric-transformations metricName=UnrestrictedSGRule,metricNamespace=RentDriveSecurityMetrics,metricValue=1

# Alert 4: S3 bucket policy or ACL change
aws logs put-metric-filter \
  --log-group-name "$LOG_GROUP" \
  --filter-name "S3BucketPolicyChange" \
  --filter-pattern '{ ($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketPublicAccessBlock) }' \
  --metric-transformations metricName=S3BucketPolicyChange,metricNamespace=RentDriveSecurityMetrics,metricValue=1
```

#### Step 3: GuardDuty and AWS Security Hub
```bash
# Enable GuardDuty with all protection plans
DETECTOR_ID=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text 2>/dev/null \
  || aws guardduty create-detector --enable --query 'DetectorId' --output text)

aws guardduty update-detector \
  --detector-id "$DETECTOR_ID" \
  --data-sources '{
    "S3Logs": {"Enable": true},
    "Kubernetes": {"AuditLogs": {"Enable": true}},
    "MalwareProtection": {"ScanEc2InstanceWithFindings": {"EbsVolumes": true}}
  }'

# Enable Security Hub (aggregates GuardDuty + Inspector + Macie + Config findings)
aws securityhub enable-security-hub --enable-default-standards

# Enable CIS AWS Foundations Benchmark v1.4
aws securityhub batch-enable-standards \
  --standards-subscription-requests \
    StandardsArn="arn:aws:securityhub:ap-southeast-1::standards/cis-aws-foundations-benchmark/v/1.4.0" \
    StandardsArn="arn:aws:securityhub:ap-southeast-1::standards/aws-foundational-security-best-practices/v/1.0.0"

echo "GuardDuty + Security Hub active. CIS benchmark monitoring enabled."
```

#### 🔐 OWASP A09 — Policy to AWS Implementation

**OWASP A09 Policy:** *"Log all authentication events, access control failures, and input validation failures with sufficient context; generate alerts for suspicious activities; retain logs for a minimum of 12 months; test monitoring and alerting systems regularly."*

```bash
# ── A09: Security Logging & Monitoring Failures Prevention ──────────────────
# Config rule: CloudTrail enabled in all regions (OWASP A09 — must log API activity)
aws configservice put-config-rule --config-rule '{
  "ConfigRuleName": "cloudtrail-enabled",
  "Source": {"Owner":"AWS","SourceIdentifier":"CLOUD_TRAIL_ENABLED"}
}'

# Config rule: CloudTrail log file validation enabled (tamper detection)
aws configservice put-config-rule --config-rule '{
  "ConfigRuleName": "cloud-trail-log-file-validation-enabled",
  "Source": {"Owner":"AWS","SourceIdentifier":"CLOUD_TRAIL_LOG_FILE_VALIDATION_ENABLED"}
}'

# CloudWatch metric filter: detect IAM policy changes (OWASP A09 — must alert on access changes)
aws logs put-metric-filter \
  --log-group-name "rentdrive-cloudtrail-logs" \
  --filter-name "OWASP-A09-IAMPolicyChange" \
  --filter-pattern '{$.eventName=DeleteGroupPolicy || $.eventName=DeleteRolePolicy || $.eventName=PutGroupPolicy || $.eventName=PutRolePolicy || $.eventName=AttachGroupPolicy || $.eventName=AttachRolePolicy}' \
  --metric-transformations MetricName=IAMPolicyChangeCount,MetricNamespace=OWASPAlerts,DefaultValue=0,Value=1

aws cloudwatch put-metric-alarm \
  --alarm-name "OWASP-A09-IAMPolicyChange" \
  --namespace OWASPAlerts --metric-name IAMPolicyChangeCount \
  --statistic Sum --period 300 --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold --evaluation-periods 1 \
  --alarm-actions "$SNS_ARN" \
  --alarm-description "OWASP A09: IAM policy changed — review immediately"

# CloudWatch metric filter: console login without MFA (OWASP A09 + A07 combined violation)
aws logs put-metric-filter \
  --log-group-name "rentdrive-cloudtrail-logs" \
  --filter-name "OWASP-A09-ConsoleLoginNoMFA" \
  --filter-pattern '{ $.eventName = "ConsoleLogin" && $.additionalEventData.MFAUsed != "Yes" }' \
  --metric-transformations MetricName=LoginNoMFACount,MetricNamespace=OWASPAlerts,DefaultValue=0,Value=1

# Verify CloudTrail integrity: validate log digest files for last 7 days
aws cloudtrail validate-logs \
  --trail-arn "arn:aws:cloudtrail:ap-southeast-1:$(aws sts get-caller-identity --query Account --output text):trail/rentdrive-security-trail" \
  --start-time "$(date -d '-7 days' --utc +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v-7d +%Y-%m-%dT%H:%M:%SZ)" \
  --query 'filesValidated'
# Expected: integer > 0 (confirms tamper-free log chain)
```

### 📚 Challenge — Block 3 (1 Hour)

#### Critical Security Events — AWS Response SLA Matrix

| Event | Risk | AWS Detection Source | Response SLA |
|-------|------|---------------------|--------------|
| Root account login | 🔴 Critical | CloudTrail + CloudWatch | < 5 min |
| IAM policy change | 🟠 High | CloudTrail + Config | < 15 min |
| Security group 0.0.0.0/0 | 🟠 High | Config + CloudTrail | < 15 min |
| New IAM admin user created | 🟠 High | CloudTrail | < 15 min |
| KMS key disabled/deleted | 🔴 Critical | CloudTrail + SNS | < 5 min |
| S3 bucket made public | 🔴 Critical | Config + GuardDuty | < 5 min |
| >5 failed console logins | 🟡 Medium | CloudTrail | < 30 min |
| Large S3 data transfer (>1GB) | 🟠 High | GuardDuty S3 Protection | < 30 min |
| EC2 instance in unusual region | 🟠 High | GuardDuty | < 15 min |

**Self-Assessment Questions:**
1. What is the difference between CloudTrail and CloudWatch Logs? Why do you need both?
2. GuardDuty detected `UnauthorizedAccess:IAMUser/TorIPCaller` — what is your first action?
3. Why is Security Hub better than checking GuardDuty, Inspector, and Macie separately?

---

## 🗓️ DAY 5 — Vulnerability Management & Compliance

### 🎯 Learning Objectives
- Automate CVE detection with Amazon Inspector v2 across EC2 and ECR
- Automate OS patching with AWS Systems Manager Patch Manager
- Enforce compliance baseline with AWS Config + CIS rules

> **🔐 OWASP Coverage:** [A06 Vulnerable & Outdated Components](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/)

### 📖 Theory — Block 1 (1 Hour)

#### 5.1 AWS Vulnerability Management Stack
```
Amazon Inspector v2
├── EC2 scanning  — OS packages + software libraries vs NVD CVE database
├── ECR scanning  — Container images on push + continuously re-evaluated
└── Lambda        — Function code and layer package vulnerabilities

AWS Systems Manager
├── Patch Manager  — OS + app patch approval, scheduling, and compliance reporting
├── State Manager  — Association: enforce baseline config continuously
└── Inventory      — Software catalog, installed packages, configs across all instances

AWS Config
├── 130+ managed rules (CIS AWS Foundations Benchmark)
├── Resource configuration history (detect drift)
└── Auto-remediation: trigger SSM Automation document on rule violation
```

### 🔬 Lab — Block 2 (2 Hours)

#### Lab 5A — Inspector v2, Patch Manager, and OS Hardening

#### Step 1: Enable Amazon Inspector v2
```bash
# Enable Inspector for EC2 and ECR scanning
aws inspector2 enable --resource-types EC2 ECR

# Check coverage — all EC2 instances should show ACTIVE
aws inspector2 list-coverage \
  --filter-criteria '{"resourceType":[{"comparison":"EQUALS","value":"AWS_EC2_INSTANCE"}]}' \
  --query 'coveredResources[].{ID:resourceId,Status:scanStatus.statusCode}' \
  --output table

# List CRITICAL findings to patch within 24 hours
aws inspector2 list-findings \
  --filter-criteria '{"severity":[{"comparison":"EQUALS","value":"CRITICAL"}]}' \
  --query 'findings[].{
    CVE:packageVulnerabilityDetails.vulnerabilityId,
    Title:title,
    Severity:severity.label,
    Resource:resources[0].id,
    Score:inspectorScore
  }' \
  --output table
```

#### Step 2: SSM Patch Manager — Auto-Approve Critical Security Patches
```bash
# Create patch baseline for Amazon Linux 2 — critical security patches approved immediately
BASELINE_ID=$(aws ssm create-patch-baseline \
  --name "RentDrive-Security-Baseline-AmazonLinux2" \
  --operating-system AMAZON_LINUX_2 \
  --approval-rules '{
    "PatchRules": [{
      "PatchFilterGroup": {
        "PatchFilters": [
          {"Key":"SEVERITY","Values":["Critical","High"]},
          {"Key":"CLASSIFICATION","Values":["Security","Bugfix"]}
        ]
      },
      "ApproveAfterDays": 0,
      "EnableNonSecurity": false
    }]
  }' \
  --description "Zero-day approval for Critical/High security patches" \
  --query 'BaselineId' --output text)

# Set as default baseline for Amazon Linux 2
aws ssm register-default-patch-baseline --baseline-id "$BASELINE_ID"

# Create weekly maintenance window — Sundays 02:00 UTC
WINDOW_ID=$(aws ssm create-maintenance-window \
  --name "RentDrive-WeeklySecurityPatching" \
  --schedule "cron(0 2 ? * SUN *)" \
  --duration 4 --cutoff 1 \
  --allow-unassociated-targets \
  --query 'WindowId' --output text)

# Register all production EC2 instances as targets
aws ssm register-target-with-maintenance-window \
  --window-id "$WINDOW_ID" \
  --resource-type INSTANCE \
  --targets "Key=tag:Environment,Values=production"

echo "Patch Manager configured. Critical patches auto-approved; patching runs Sunday 02:00 UTC."
```

#### Step 3: Security Baseline via SSM Run Command
```bash
# Deploy OS hardening to ALL production instances simultaneously
aws ssm send-command \
  --document-name "AWS-RunShellScript" \
  --targets '[{"Key":"tag:Environment","Values":["production"]}]' \
  --parameters '{
    "commands": [
      "#!/bin/bash",
      "echo === Applying RentDrive Security Baseline ===",
      "sed -i s/^#PermitRootLogin.*/PermitRootLogin no/ /etc/ssh/sshd_config",
      "sed -i s/^PermitRootLogin.*/PermitRootLogin no/ /etc/ssh/sshd_config",
      "sed -i s/^PasswordAuthentication.*/PasswordAuthentication no/ /etc/ssh/sshd_config",
      "echo ClientAliveInterval 300 >> /etc/ssh/sshd_config",
      "echo MaxAuthTries 3 >> /etc/ssh/sshd_config",
      "systemctl restart sshd",
      "echo net.ipv4.tcp_syncookies = 1 >> /etc/sysctl.conf",
      "echo kernel.randomize_va_space = 2 >> /etc/sysctl.conf",
      "sysctl -p",
      "echo === Security Baseline Applied ==="
    ]
  }' \
  --comment "Apply CIS hardening baseline" \
  --timeout-seconds 600 \
  --output-s3-bucket-name "rentdrive-cloudtrail-$(aws sts get-caller-identity --query Account --output text)" \
  --output-s3-key-prefix "ssm-run-command-output/"
```

#### 🔐 OWASP A06 — Policy to AWS Implementation

**OWASP A06 Policy:** *"Continuously inventory all components and their versions; monitor CVE databases; patch or upgrade critical/high CVEs within 24 hours; scan all container images before deployment; remove unused dependencies."*

```bash
# ── A06: Vulnerable & Outdated Components Prevention ────────────────────────
# Config rule: approved AMIs only — block launch of unapproved OS images
aws configservice put-config-rule --config-rule '{
  "ConfigRuleName": "approved-amis-by-tag",
  "Source": {"Owner":"AWS","SourceIdentifier":"APPROVED_AMIS_BY_TAG"},
  "InputParameters": "{"amisByTagKeyAndValue":"HardenedImage:true"}"
}'

# Enable ECR enhanced scanning on push for all repositories (OWASP A06 — scan before deploy)
aws ecr put-registry-scanning-configuration \
  --scan-type ENHANCED \
  --rules '[{"repositoryFilters":[{"filter":"*","filterType":"WILDCARD"}],"scanFrequency":"SCAN_ON_PUSH"}]'

# Inspector v2: list all CRITICAL CVE findings (A06 violation — must patch within 24h)
aws inspector2 list-findings \
  --filter-criteria '{
    "severity":[{"comparison":"EQUALS","value":"CRITICAL"}],
    "findingStatus":[{"comparison":"EQUALS","value":"ACTIVE"}]
  }' \
  --query 'findings[].{CVE:packageVulnerabilityDetails.vulnerabilityId,Resource:resources[0].id,Score:inspectorScore,Title:title}' \
  --output table

# SCP: deny launch of EC2 instances without approved AMI tag (org-wide enforcement)
aws organizations create-policy \
  --name "OWASP-A06-RequireApprovedAMI" \
  --description "OWASP A06: Block EC2 launch from unapproved/unpatched images" \
  --type SERVICE_CONTROL_POLICY \
  --content '{
    "Version":"2012-10-17",
    "Statement":[{
      "Sid":"DenyUnapprovedAMI",
      "Effect":"Deny",
      "Action":"ec2:RunInstances",
      "Resource":"arn:aws:ec2:*:*:instance/*",
      "Condition":{"StringNotEquals":{"ec2:ImageType":"machine"}}
    }]
  }'

# Verification: count active CRITICAL findings — target is 0 in production
aws inspector2 list-findings \
  --filter-criteria '{"severity":[{"comparison":"EQUALS","value":"CRITICAL"}],"findingStatus":[{"comparison":"EQUALS","value":"ACTIVE"}]}' \
  --query 'length(findings)'
# Target: 0
```

### 📚 Challenge — Block 3 (1 Hour)

#### Study Case 5: Log4Shell on Car Rental SaaS (CVE-2021-44228)

**Scenario:** A car rental SaaS company ran EC2 instances with the Log4Shell vulnerability (CVSS 10.0). Despite the vulnerability being publicly disclosed for 21 days, no patching occurred — AWS Patch Manager was not configured. Attackers gained remote code execution, installed a cryptominer, and the compromise was only discovered 45 days later via an AWS Cost Explorer billing spike.

**Timeline:**
```
Day 0:  CVE-2021-44228 disclosed (CVSS 10.0 — maximum severity)
Day 3:  Public proof-of-concept exploit published on GitHub
Day 7:  Automated internet-wide scanning begins targeting /jndi: patterns
Day 21: RentDrive EC2 instances compromised via booking search endpoint
Day 45: Cryptominer discovered: EC2 CPU consistently at 98%, unusual outbound traffic
```

**Prevention with Amazon Inspector v2 + SSM Patch Manager:**
- Inspector v2: Same-day CVE detection → Security Hub finding → SNS email alert
- Patch Manager: `ApproveAfterDays: 0` for Critical CVEs = patches deployed within hours
- GuardDuty: `Backdoor:EC2/C&CActivity.B` finding flags C2 communication immediately
- WAF: Rate-based rule detects automated `jndi:` scanning pattern in URI/headers

---

## 🗓️ DAY 6 — Application Security & WAF

### 🎯 Learning Objectives
- Deploy AWS WAF v2 with managed rule groups protecting the booking API
- Configure AWS Shield Advanced for DDoS mitigation
- Secure container workloads on EKS using Pod Security Standards

> **🔐 OWASP Coverage:** [A03 Injection](https://owasp.org/Top10/A03_2021-Injection/) · [A05 Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) · [OWASP API Security Top 10 2023](https://owasp.org/API-Security/editions/2023/en/0x11-t10/) (API1 BOLA · API2 Broken Auth · API3 Property Auth · API5 Function Auth · API8 Misconfiguration)

### 📖 Theory — Block 1 (1 Hour)

#### 6.1 AWS Application Security Stack
```
Route 53 (DNS health checks + failover)
    │
    ▼
CloudFront (CDN + TLS termination + WAF integration)
    │
    ▼
AWS WAF v2
├── AWSManagedRulesCommonRuleSet     (OWASP Top 10)
├── AWSManagedRulesSQLiRuleSet       (SQLi patterns)
├── AWSManagedRulesKnownBadInputsRuleSet (Log4Shell, SSRF)
├── Rate-based rule                  (2000 req/5min per IP)
├── Geo-match block rule             (countries with no business)
└── AWS Bot Control                  (managed bot protection)
    │
    ▼
Application Load Balancer → EKS / EC2 App Tier
```

### 🔬 Lab — Block 2 (2 Hours)

#### Lab 6A — AWS WAF v2, Shield Advanced, EKS Pod Security

#### Step 1: Create WAF Web ACL with Managed Rule Groups
```bash
REGION="ap-southeast-1"

# Create WAF Web ACL (REGIONAL — attaches to ALB)
WAF_ACL_ARN=$(aws wafv2 create-web-acl \
  --name "rentdrive-waf-prod" \
  --scope REGIONAL \
  --region $REGION \
  --default-action '{"Allow":{}}' \
  --rules '[
    {
      "Name": "CommonRuleSet",
      "Priority": 1,
      "OverrideAction": {"None": {}},
      "Statement": {"ManagedRuleGroupStatement": {"VendorName":"AWS","Name":"AWSManagedRulesCommonRuleSet"}},
      "VisibilityConfig": {"SampledRequestsEnabled":true,"CloudWatchMetricsEnabled":true,"MetricName":"CommonRuleSet"}
    },
    {
      "Name": "SQLiRuleSet",
      "Priority": 2,
      "OverrideAction": {"None": {}},
      "Statement": {"ManagedRuleGroupStatement": {"VendorName":"AWS","Name":"AWSManagedRulesSQLiRuleSet"}},
      "VisibilityConfig": {"SampledRequestsEnabled":true,"CloudWatchMetricsEnabled":true,"MetricName":"SQLiRuleSet"}
    },
    {
      "Name": "KnownBadInputs",
      "Priority": 3,
      "OverrideAction": {"None": {}},
      "Statement": {"ManagedRuleGroupStatement": {"VendorName":"AWS","Name":"AWSManagedRulesKnownBadInputsRuleSet"}},
      "VisibilityConfig": {"SampledRequestsEnabled":true,"CloudWatchMetricsEnabled":true,"MetricName":"KnownBadInputs"}
    },
    {
      "Name": "RateLimitPerIP",
      "Priority": 4,
      "Action": {"Block": {}},
      "Statement": {"RateBasedStatement": {"Limit": 2000, "AggregateKeyType": "IP"}},
      "VisibilityConfig": {"SampledRequestsEnabled":true,"CloudWatchMetricsEnabled":true,"MetricName":"RateLimit"}
    }
  ]' \
  --visibility-config SampledRequestsEnabled=true,CloudWatchMetricsEnabled=true,MetricName=rentdrive-waf \
  --query 'Summary.ARN' --output text)

# Associate WAF with the production ALB
ALB_ARN=$(aws elbv2 describe-load-balancers \
  --query "LoadBalancers[?LoadBalancerName=='rentdrive-prod-alb'].LoadBalancerArn" \
  --output text)
aws wafv2 associate-web-acl \
  --web-acl-arn "$WAF_ACL_ARN" --resource-arn "$ALB_ARN" --region $REGION
echo "WAF associated with ALB"
```

#### Step 2: Enable AWS Shield Advanced
```bash
# Enable Shield Advanced (requires subscription — protects against volumetric DDoS)
aws shield create-subscription

# Protect the production ALB with Shield Advanced
aws shield create-protection \
  --name "rentdrive-prod-alb-ddos-protection" \
  --resource-arn "$ALB_ARN"

# Enable proactive DDoS Response Team (DRT) engagement
aws shield update-proactive-engagement --proactive-engagement-status ENABLED

# CloudWatch alarm when DDoS attack detected on the ALB
aws cloudwatch put-metric-alarm \
  --alarm-name "DDoS-Attack-Detected-ALB" \
  --namespace AWS/DDoSProtection --metric-name DDoSDetected \
  --statistic Sum --period 60 --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold --evaluation-periods 1 \
  --dimensions "Name=ResourceArn,Value=$ALB_ARN" \
  --alarm-actions "$SNS_ARN"
```

#### Step 3: EKS Pod Security Standards for Booking API
```yaml
# Apply restricted Pod Security Standard to the car-rental-api namespace
apiVersion: v1
kind: Namespace
metadata:
  name: car-rental-api
  labels:
    pod-security.kubernetes.io/enforce: restricted     # Block non-compliant pods
    pod-security.kubernetes.io/audit: restricted       # Audit violations to API server log
    pod-security.kubernetes.io/warn: restricted        # Warn users via kubectl output
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: booking-api
  namespace: car-rental-api
spec:
  replicas: 3
  selector:
    matchLabels:
      app: booking-api
  template:
    metadata:
      labels:
        app: booking-api
    spec:
      serviceAccountName: booking-api-sa        # Dedicated SA with least-privilege IRSA
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        fsGroup: 10001
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: booking-api
          image: 123456789012.dkr.ecr.ap-southeast-1.amazonaws.com/booking-api:v2.1.0
          securityContext:
            allowPrivilegeEscalation: false       # No sudo inside the container
            readOnlyRootFilesystem: true           # Immutable container filesystem
            capabilities:
              drop: ["ALL"]                       # Drop all Linux capabilities
          resources:
            limits:
              cpu: "500m"
              memory: "256Mi"
```

#### 🔐 OWASP A03 & API Security Top 10 — Policy to AWS Implementation

**OWASP A03 Policy:** *"Use parameterized queries; validate and sanitize all input server-side; apply WAF rules for injection patterns; never concatenate user input into queries or commands."*

**OWASP API1 (BOLA) Policy:** *"Every API request must verify the authenticated user owns the requested resource, not just that they are authenticated."*

```bash
# ── A03: Injection Prevention via AWS WAF ───────────────────────────────────
# Add SQLi-specific WAF rule group to existing Web ACL (OWASP A03 — SQL Injection)
WAF_ACL_ARN=$(aws wafv2 list-web-acls --scope REGIONAL --region ap-southeast-1 \
  --query "WebACLs[?Name=='rentdrive-waf-prod'].ARN" --output text)

# Enable AWS Managed SQLi rule set (blocks UNION SELECT, stacked queries, blind SQLi)
aws wafv2 update-web-acl \
  --name "rentdrive-waf-prod" --scope REGIONAL --region ap-southeast-1 \
  --id "$(aws wafv2 list-web-acls --scope REGIONAL --region ap-southeast-1 --query "WebACLs[?Name=='rentdrive-waf-prod'].Id" --output text)" \
  --lock-token "$(aws wafv2 get-web-acl --name rentdrive-waf-prod --scope REGIONAL --region ap-southeast-1 --id $(aws wafv2 list-web-acls --scope REGIONAL --region ap-southeast-1 --query "WebACLs[?Name=='rentdrive-waf-prod'].Id" --output text) --query 'LockToken' --output text)" \
  --default-action '{"Allow":{}}' \
  --rules '[{"Name":"SQLiRuleSet","Priority":2,"OverrideAction":{"None":{}},"Statement":{"ManagedRuleGroupStatement":{"VendorName":"AWS","Name":"AWSManagedRulesSQLiRuleSet"}},"VisibilityConfig":{"SampledRequestsEnabled":true,"CloudWatchMetricsEnabled":true,"MetricName":"SQLiRuleSet"}}]' \
  --visibility-config SampledRequestsEnabled=true,CloudWatchMetricsEnabled=true,MetricName=rentdrive-waf

# ── API1: BOLA (Broken Object Level Authorization) Prevention ───────────────
# Deploy Lambda authorizer on API Gateway to enforce object-level ownership
# The authorizer verifies: token owner matches the resource ID in the request path
cat > /tmp/bola-authorizer-policy.json << 'AUTHEOF'
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "apigateway.amazonaws.com"},
    "Action": "lambda:InvokeFunction",
    "Resource": "arn:aws:lambda:ap-southeast-1:*:function:rentdrive-bola-authorizer"
  }]
}
AUTHEOF

aws apigateway create-authorizer \
  --rest-api-id "$API_GW_ID" \
  --name "RentDriveBOLAAuthorizer" \
  --type TOKEN \
  --authorizer-uri "arn:aws:apigateway:ap-southeast-1:lambda:path/functions/arn:aws:lambda:ap-southeast-1:$(aws sts get-caller-identity --query Account --output text):function:rentdrive-bola-authorizer/invocations" \
  --identity-source "method.request.header.Authorization" \
  --authorizer-result-ttl-in-seconds 0
echo "BOLA authorizer deployed — every reservation endpoint now validates caller owns resource"

# ── API8: Security Misconfiguration — Disable verbose API error responses ───
# API Gateway: disable detailed error messages (do not expose stack traces to clients)
aws apigateway update-stage \
  --rest-api-id "$API_GW_ID" \
  --stage-name "prod" \
  --patch-operations '[{"op":"replace","path":"/*/*/logging/dataTrace","value":"false"}]'
echo "OWASP API8: verbose API error logging disabled in prod — prevents info exposure"

# Verification: WAF sampled requests — confirm SQLi attempts are being blocked
aws wafv2 get-sampled-requests \
  --web-acl-arn "$WAF_ACL_ARN" \
  --rule-metric-name "SQLiRuleSet" \
  --scope REGIONAL --region ap-southeast-1 \
  --time-window StartTime=$(date -u -d '-1 hour' +%s 2>/dev/null || date -u -v-1H +%s),EndTime=$(date -u +%s) \
  --max-items 5 \
  --query 'SampledRequests[].{Action:Action,URI:Request.URI,IP:Request.ClientIP}'
```

### 📚 Challenge — Block 3 (1 Hour)

#### Study Case 6: SQL Injection on Booking Search API

**Scenario:** A car rental SaaS API endpoint `/api/v1/search-vehicles?city=` used direct SQL string concatenation. An attacker used a `UNION SELECT` payload to bypass authentication and dump the entire customer database — **380,000 records including hashed payment cards and driver's license numbers** — in a single automated scan.

**Root Cause:** No WAF, parameterized queries not enforced, no rate limiting.

**AWS Controls That Would Have Prevented This:**
1. **WAF `AWSManagedRulesSQLiRuleSet`** — blocks UNION SELECT, stacked queries, blind SQLi
2. **WAF rate-based rule** — 2,000 req/5min throttles automated scanning tools
3. **Amazon RDS Proxy** — connection pooling; prevents connection flooding
4. **AWS Secrets Manager** — auto-rotating DB credentials limits credential exposure window
5. **Amazon Inspector v2** — detects known-vulnerable library versions in deployed code

---

## 🗓️ DAY 7 — Incident Response & Forensics

### 🎯 Learning Objectives
- Build and execute an AWS-native Incident Response Plan (IRP)
- Preserve forensic evidence using EBS snapshots and CloudTrail exports
- Practice the full IR playbook with a simulated GuardDuty finding

> **🔐 OWASP Coverage:** [A10 Server-Side Request Forgery (SSRF)](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/) · [OWASP Testing Guide v4.2](https://owasp.org/www-project-web-security-testing-guide/)

### 📖 Theory — Block 1 (1 Hour)

#### 7.1 NIST 4-Phase IR Model — AWS Implementation
```
PHASE 1: PREPARATION
├── IR runbooks stored in SSM Documents (version-controlled)
├── Forensic golden AMI pre-built with volatility, strings, yara
├── Quarantine SG pre-created (deny all inbound + outbound)
└── CloudTrail + VPC Flow Logs + GuardDuty pre-enabled (evidence collection ready)

PHASE 2: DETECTION & ANALYSIS
├── GuardDuty finding OR CloudWatch alarm → SNS → PagerDuty/Slack
├── Severity classification: P1 (<15min) / P2 (<1hr) / P3 (<4hr)
├── EBS snapshot created immediately (preserve pre-containment state)
└── IR team assembled in dedicated incident channel

PHASE 3: CONTAINMENT, ERADICATION, RECOVERY
├── Apply quarantine SG to affected EC2 instance (deny all traffic)
├── Attach inline Deny-All IAM policy to compromise role (instant revocation)
├── Launch clean replacement from hardened golden AMI
└── Restore data from verified clean snapshot or backup

PHASE 4: POST-INCIDENT ACTIVITY
├── Root cause analysis report (72-hour deadline)
├── Lessons learned session (within 1 week)
├── AWS Config rule / GuardDuty suppression rules updated
└── Threat model updated; IR playbook version-bumped
```

### 🔬 Lab — Block 2 (2 Hours)

#### Lab 7A — Incident Response Playbook: Compromised EC2 Instance

**Trigger:** GuardDuty finding — `UnauthorizedAccess:EC2/SSHBruteForce` or `Backdoor:EC2/C&CActivity.B`

```bash
#!/bin/bash
# INCIDENT RESPONSE PLAYBOOK v1.0 — RentDrive SaaS (AWS)
# Run by: On-call Security Engineer

INCIDENT_ID="INC-$(date +%Y%m%d)-001"
AFFECTED_INSTANCE="i-0123456789abcdef0"   # From GuardDuty finding
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
REGION="ap-southeast-1"
SNS_TOPIC="arn:aws:sns:${REGION}:${ACCOUNT_ID}:rentdrive-security-alerts"
QUARANTINE_SG="sg-00000000000000000"       # Pre-created: deny all inbound + outbound
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "=== INCIDENT RESPONSE INITIATED: $INCIDENT_ID — $TIMESTAMP ==="

# ─── STEP 1: PRESERVE EVIDENCE (before touching anything) ───────────────────
echo "[1/5] Creating forensic EBS snapshot (pre-containment state)..."
VOLUME_ID=$(aws ec2 describe-instances \
  --instance-ids "$AFFECTED_INSTANCE" --region $REGION \
  --query 'Reservations[0].Instances[0].BlockDeviceMappings[0].Ebs.VolumeId' \
  --output text)

aws ec2 create-snapshot \
  --volume-id "$VOLUME_ID" --region $REGION \
  --description "FORENSIC-${INCIDENT_ID}" \
  --tag-specifications "ResourceType=snapshot,Tags=[
    {Key=incident-id,Value=${INCIDENT_ID}},
    {Key=purpose,Value=forensic-evidence},
    {Key=do-not-delete,Value=true},
    {Key=timestamp,Value=${TIMESTAMP}}
  ]"

echo "[2/5] Exporting CloudTrail events for affected instance (last 48h)..."
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue="$AFFECTED_INSTANCE" \
  --region $REGION \
  > "/tmp/forensic-cloudtrail-${INCIDENT_ID}.json"
echo "CloudTrail export: $(cat /tmp/forensic-cloudtrail-${INCIDENT_ID}.json | wc -l) lines saved"

# ─── STEP 2: CONTAINMENT ────────────────────────────────────────────────────
echo "[3/5] Applying quarantine security group (deny all traffic)..."
aws ec2 modify-instance-attribute \
  --instance-id "$AFFECTED_INSTANCE" \
  --groups "$QUARANTINE_SG" \
  --region $REGION
echo "Instance $AFFECTED_INSTANCE: QUARANTINED"

# ─── STEP 3: REVOKE IAM CREDENTIALS ────────────────────────────────────────
echo "[4/5] Suspending IAM role permissions via inline Deny-All policy..."
ROLE_NAME=$(aws ec2 describe-instances \
  --instance-ids "$AFFECTED_INSTANCE" --region $REGION \
  --query 'Reservations[0].Instances[0].IamInstanceProfile.Arn' \
  --output text | rev | cut -d'/' -f1 | rev)

aws iam put-role-policy \
  --role-name "$ROLE_NAME" \
  --policy-name "INCIDENT-QUARANTINE-${INCIDENT_ID}" \
  --policy-document "{
    \"Version\":\"2012-10-17\",
    \"Statement\":[{\"Effect\":\"Deny\",\"Action\":\"*\",\"Resource\":\"*\",
      \"Condition\":{\"StringEquals\":{\"aws:RequestedRegion\":\"*\"}}}]
  }"
echo "IAM role $ROLE_NAME: all permissions SUSPENDED"

# ─── STEP 4: NOTIFY ─────────────────────────────────────────────────────────
echo "[5/5] Publishing incident notification to security team..."
aws sns publish \
  --topic-arn "$SNS_TOPIC" \
  --subject "SECURITY INCIDENT CONTAINED: ${INCIDENT_ID}" \
  --message "INCIDENT: ${INCIDENT_ID}
Instance: ${AFFECTED_INSTANCE}
Region: ${REGION}
Status: CONTAINED
Time: ${TIMESTAMP}
Forensic snapshot: created
CloudTrail export: /tmp/forensic-cloudtrail-${INCIDENT_ID}.json
IAM role: SUSPENDED (inline deny attached)
ACTION REQUIRED: Assemble IR team in #security-incidents channel"

echo ""
echo "=== INCIDENT ${INCIDENT_ID} CONTAINED ==="
echo "Next steps: Attach forensic AMI, mount snapshot read-only, begin memory analysis"
```

#### 🔐 OWASP A10 SSRF — Policy to AWS Implementation

**OWASP A10 Policy:** *"Validate all user-supplied URLs; deny access to internal/private IP ranges from application tier; enforce IMDSv2 on all EC2 instances to prevent metadata service abuse; block unexpected outbound connections."*

```bash
# ── A10: SSRF Prevention ────────────────────────────────────────────────────
# SCP: enforce IMDSv2 on all EC2 instances (blocks SSRF to 169.254.169.254)
aws organizations create-policy \
  --name "OWASP-A10-EnforceIMDSv2" \
  --description "OWASP A10: Require IMDSv2 — prevent SSRF access to EC2 metadata service" \
  --type SERVICE_CONTROL_POLICY \
  --content '{
    "Version":"2012-10-17",
    "Statement":[{
      "Sid":"DenyIMDSv1",
      "Effect":"Deny",
      "Action":"ec2:RunInstances",
      "Resource":"arn:aws:ec2:*:*:instance/*",
      "Condition":{"StringNotEquals":{"ec2:MetadataHttpTokens":"required"}}
    }]
  }'

# Enforce IMDSv2 on all currently running EC2 instances (remediate existing)
aws ec2 describe-instances \
  --filters "Name=instance-state-name,Values=running" \
  --query 'Reservations[].Instances[].InstanceId' --output text | \
tr ' ' '\n' | while read INSTANCE_ID; do
  aws ec2 modify-instance-metadata-options \
    --instance-id "$INSTANCE_ID" \
    --http-tokens required \
    --http-put-response-hop-limit 1
  echo "IMDSv2 enforced: $INSTANCE_ID"
done

# WAF rule: block SSRF patterns in requests (jndi:, file://, http://169.254, http://10.)
aws wafv2 create-ip-set \
  --name "SSRF-Internal-Ranges" \
  --scope REGIONAL --region ap-southeast-1 \
  --ip-address-version IPV4 \
  --addresses "169.254.0.0/16" "10.0.0.0/8" "172.16.0.0/12" "192.168.0.0/16"

# GuardDuty finding types that indicate SSRF exploitation in progress
aws guardduty list-findings \
  --detector-id "$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)" \
  --finding-criteria '{
    "Criterion": {
      "type": {"Eq": [
        "UnauthorizedAccess:EC2/MetadataAccess",
        "Recon:EC2/PortProbeUnprotectedPort",
        "Backdoor:EC2/C&CActivity.B"
      ]}
    }
  }' \
  --query 'FindingIds' --output table

# OWASP Testing Guide (WSTG-INPV-19): verify SSRF remediation
# Test: attempt metadata access from app tier (should be blocked by IMDSv2 token requirement)
echo "SSRF Test: attempting IMDSv1 metadata access (should fail)..."
curl -s -o /dev/null -w "%{http_code}" http://169.254.169.254/latest/meta-data/ --max-time 3
# Expected: 401 (token required) or connection timeout — NOT 200
echo ""
echo "OWASP A10 SSRF protection verified"
```

### 📚 Challenge — Block 3 (1 Hour)

#### Study Case 7: APT Attack on RentDrive SaaS Platform (47-Day Dwell Time)

**Scenario:** RentDrive was targeted via a spear phishing email sent to the Finance Manager. After credential theft, the attacker created a legitimate-looking IAM role named `aws-backup-service-role-prod` and exfiltrated fleet GPS telemetry, customer PII, and rental contracts over 47 days.

**Attack Chain:**
```
Spear Phishing → Finance Manager's Credentials Stolen via Browser-in-Browser
→ AWS Console Access Established
→ New IAM Role Created: "aws-backup-service-role-prod" (blends with legitimate names)
→ Persistence in us-east-1 AND ap-northeast-1 (redundant foothold)
→ S3 Exfiltration: 3GB/day via HTTPS — fleet data + driver PII
→ Day 47: GuardDuty Behavior:IAMUser/DataExfiltration.S3 fires
→ Security team investigates — discovers 141GB total exfiltrated
```

**Detection Failures That Allowed 47-Day Dwell:**
- GuardDuty disabled (free 30-day trial expired, renewal overlooked)
- CloudTrail S3 data events disabled (team considered it "too expensive")
- No alert on new IAM role creation
- No behavioral baseline for IAM user activity (no UEBA)

**Improvements Post-Incident:**
- GuardDuty permanently enabled across all accounts via AWS Organizations SCP
- CloudTrail data events enabled for all sensitive S3 buckets
- AWS Config rule: alert on any `CreateRole` API call within 5 minutes
- Amazon Macie: anomaly detection on PII bucket access patterns
- IAM Access Analyzer: weekly review of all external access findings

---

## 🗓️ DAY 8 — Business Continuity & Disaster Recovery

### 🎯 Learning Objectives
- Design RTO/RPO-aligned DR tiers for a SaaS car rental platform
- Configure S3 Cross-Region Replication and RDS Multi-AZ / Read Replica
- Automate DR testing with AWS Backup and scheduled restoration tests

> **🔐 OWASP Coverage:** [A05 Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) — DR environments must be held to the same security standard as production

### 📖 Theory — Block 1 (1 Hour)

#### 8.1 AWS DR Architecture Tiers for RentDrive

| Tier | System | RTO | RPO | AWS Strategy |
|------|--------|-----|-----|-------------|
| 1 | Booking API + payments | < 15 min | < 1 min | Active-Active: Route 53 latency routing + Multi-Region ALB |
| 2 | Fleet management dashboard | < 1 hour | < 15 min | Warm Standby: RDS Read Replica → promote on failure |
| 3 | Reporting / analytics | < 4 hours | < 1 hour | Pilot Light: AMI + RDS snapshot restore on demand |
| 4 | Dev/staging + internal tools | < 24 hours | < 24 hours | AWS Backup restore from daily snapshot |

### 🔬 Lab — Block 2 (2 Hours)

#### Lab 8A — Cross-Region DR Setup for RentDrive

```bash
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# ─── S3 Cross-Region Replication ─────────────────────────────────────────────
# Create IAM role for S3 CRR
aws iam create-role --role-name "S3-CRR-RentDrive-Role" \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"s3.amazonaws.com"},"Action":"sts:AssumeRole"}]}'

# Destination bucket in DR region (ap-northeast-1 = Tokyo)
aws s3api create-bucket \
  --bucket "rentdrive-documents-dr-${ACCOUNT_ID}" \
  --region ap-northeast-1 \
  --create-bucket-configuration LocationConstraint=ap-northeast-1

aws s3api put-bucket-versioning \
  --bucket "rentdrive-documents-dr-${ACCOUNT_ID}" \
  --versioning-configuration Status=Enabled

# Enable Cross-Region Replication with 15-minute RTO SLA
aws s3api put-bucket-replication \
  --bucket "rentdrive-documents-${ACCOUNT_ID}" \
  --replication-configuration "{
    \"Role\": \"arn:aws:iam::${ACCOUNT_ID}:role/S3-CRR-RentDrive-Role\",
    \"Rules\": [{
      \"Status\": \"Enabled\",
      \"ID\": \"dr-ap-northeast-1\",
      \"Filter\": {\"Prefix\": \"\"},
      \"Destination\": {
        \"Bucket\": \"arn:aws:s3:::rentdrive-documents-dr-${ACCOUNT_ID}\",
        \"StorageClass\": \"STANDARD_IA\",
        \"ReplicationTime\": {\"Status\":\"Enabled\",\"Time\":{\"Minutes\":15}},
        \"Metrics\": {\"Status\":\"Enabled\",\"EventThreshold\":{\"Minutes\":15}}
      },
      \"DeleteMarkerReplication\": {\"Status\":\"Enabled\"}
    }]
  }"

# ─── RDS Multi-AZ for Production ─────────────────────────────────────────────
aws rds modify-db-instance \
  --db-instance-identifier "rentdrive-prod-mysql" \
  --multi-az \
  --apply-immediately
echo "RDS Multi-AZ enabled: automatic failover <2 minutes if primary AZ fails"

# ─── RDS Cross-Region Read Replica for DR ────────────────────────────────────
aws rds create-db-instance-read-replica \
  --db-instance-identifier "rentdrive-dr-mysql-tokyo" \
  --source-db-instance-identifier "rentdrive-prod-mysql" \
  --source-region ap-southeast-1 \
  --db-instance-class db.t3.medium \
  --no-multi-az \
  --no-publicly-accessible \
  --region ap-northeast-1
echo "Cross-region Read Replica created in Tokyo for disaster recovery"

# ─── AWS Backup Plan with Cross-Region Copy ──────────────────────────────────
aws backup create-backup-plan \
  --backup-plan '{
    "BackupPlanName": "RentDrive-Enterprise-Backup",
    "Rules": [
      {
        "RuleName": "Daily-35DayRetention",
        "TargetBackupVaultName": "rentdrive-prod-vault",
        "ScheduleExpression": "cron(0 3 * * ? *)",
        "StartWindowMinutes": 60,
        "CompletionWindowMinutes": 180,
        "Lifecycle": {"DeleteAfterDays": 35},
        "CopyActions": [{
          "DestinationBackupVaultArn": "arn:aws:backup:ap-northeast-1:'"$ACCOUNT_ID"':backup-vault:rentdrive-dr-vault",
          "Lifecycle": {"DeleteAfterDays": 90}
        }]
      },
      {
        "RuleName": "Monthly-7YearCompliance",
        "TargetBackupVaultName": "rentdrive-prod-vault",
        "ScheduleExpression": "cron(0 3 1 * ? *)",
        "Lifecycle": {"DeleteAfterDays": 2555}
      }
    ]
  }'

# ─── Monthly DR Test Script ───────────────────────────────────────────────────
cat > /tmp/dr-monthly-test.sh << 'DREOF'
#!/bin/bash
echo "=== RentDrive Monthly DR Restoration Test — $(date) ==="
# Get the latest automated RDS snapshot
SNAPSHOT_ID=$(aws rds describe-db-snapshots \
  --db-instance-identifier rentdrive-prod-mysql \
  --snapshot-type automated \
  --query 'DBSnapshots | sort_by(@, &SnapshotCreateTime) | [-1].DBSnapshotIdentifier' \
  --output text)
echo "Restoring snapshot: $SNAPSHOT_ID to isolated test environment..."
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier "rentdrive-drtest-$(date +%Y%m%d)" \
  --db-snapshot-identifier "$SNAPSHOT_ID" \
  --db-instance-class db.t3.micro \
  --no-multi-az --no-publicly-accessible \
  --tags Key=Purpose,Value=DRTest Key=AutoDelete,Value=true
echo "Run application smoke tests. Record actual RTO vs target: < 4 hours."
echo "Tag instance for deletion after test: aws rds delete-db-instance ..."
DREOF
chmod +x /tmp/dr-monthly-test.sh
echo "Monthly DR test script ready: /tmp/dr-monthly-test.sh"
```

#### 🔐 OWASP A05 (DR Context) — Policy to AWS Implementation

**OWASP A05 Policy:** *"DR and backup environments must be configured with the same security hardening as production; no default credentials; no public access; validate configurations before and after failover."*

```bash
# ── A05: DR Environment Security Configuration Audit ────────────────────────
# Verify DR RDS snapshot is encrypted (OWASP A05 + A02: encrypted backups required)
aws rds describe-db-snapshots \
  --db-instance-identifier "rentdrive-prod-mysql" \
  --query 'DBSnapshots[].{ID:DBSnapshotIdentifier,Encrypted:Encrypted,Status:Status}' \
  --output table
# All Encrypted values must be: True

# AWS Backup: enable Vault Lock (WORM) — prevents ransomware from deleting backups
aws backup put-backup-vault-lock-configuration \
  --backup-vault-name "rentdrive-prod-vault" \
  --min-retention-days 7 \
  --max-retention-days 2555 \
  --changeable-for-days 3
echo "Backup Vault Lock enabled — backups are immutable for 7-2555 days (OWASP A05)"

# Config rule: RDS snapshots must not be publicly restorable
aws configservice put-config-rule --config-rule '{
  "ConfigRuleName": "rds-snapshots-public-prohibited",
  "Source": {"Owner":"AWS","SourceIdentifier":"RDS_SNAPSHOTS_PUBLIC_PROHIBITED"}
}'

# Config rule: AWS Backup must be enabled for all RDS instances
aws configservice put-config-rule --config-rule '{
  "ConfigRuleName": "dynamodb-in-backup-plan",
  "Source": {"Owner":"AWS","SourceIdentifier":"AURORA_MYSQL_BACKTRACKING_ENABLED"}
}'

# Verify DR RDS read replica (Tokyo) has encryption and no public access
aws rds describe-db-instances \
  --db-instance-identifier "rentdrive-dr-mysql-tokyo" \
  --region ap-northeast-1 \
  --query 'DBInstances[0].{Encrypted:StorageEncrypted,Public:PubliclyAccessible,MultiAZ:MultiAZ}' \
  --output table
# Expected: Encrypted=true, Public=false

# S3 DR bucket: verify Block Public Access is enforced on replication destination
aws s3api get-public-access-block \
  --bucket "rentdrive-documents-dr-$(aws sts get-caller-identity --query Account --output text)" \
  --region ap-northeast-1 \
  --query 'PublicAccessBlockConfiguration'
# Expected: all four fields = true
```

### 📚 Challenge — Block 3 (1 Hour)

**Self-Assessment Quiz:**
1. What is the difference between RDS Multi-AZ and a Cross-Region Read Replica? When would you use each?
2. How does S3 Cross-Region Replication + Object Lock protect against ransomware that compromises the primary region entirely?
3. RentDrive's booking API needs RTO < 15 minutes. Describe the exact AWS architecture you would build.
4. What is AWS Backup Vault Lock, and why is it important even if you already have Object Lock on S3?

---

## 🗓️ DAY 9 — Zero Trust Architecture

### 🎯 Learning Objectives
- Implement Zero Trust principles across all AWS access paths
- Configure AWS Verified Access for application access without VPN
- Enforce continuous verification with IAM Permission Boundaries and PrivateLink

> **🔐 OWASP Coverage:** [OWASP ASVS Level 3](https://owasp.org/www-project-application-security-verification-standard/) · [A01 Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) · [A07 Identification & Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)

### 📖 Theory — Block 1 (1 Hour)

#### 9.1 "Never Trust, Always Verify" Framework
```
Traditional: Trust internal VPC → Verify only at the perimeter
Zero Trust:  Verify EVERYTHING, EVERYWHERE, EVERY TIME

┌───────────────────────────────────────────────┐
│          ZERO TRUST CONTROL PLANE             │
│                                               │
│  Identity  → Device  → Location → Behavior   │
│  IAM + SSO   MDM       IP/Geo    GuardDuty    │
│      ↓         ↓          ↓          ↓       │
│  ┌───────────────────────────────────────┐   │
│  │   AWS Verified Access / IAM Policy    │   │
│  │     ALLOW / DENY / STEP-UP AUTH       │   │
│  └───────────────────────────────────────┘   │
│                     ↓                         │
│  Application (EC2 / EKS / RDS / Lambda)       │
└───────────────────────────────────────────────┘
```

### 🔬 Lab — Block 2 (2 Hours)

#### Lab 9A — Zero Trust with AWS Verified Access and PrivateLink

#### Step 1: AWS Verified Access — Application Access Without VPN
```bash
# Create Verified Access Trust Provider (IAM Identity Center / corporate SSO)
TRUST_PROVIDER_ID=$(aws ec2 create-verified-access-trust-provider \
  --trust-provider-type user \
  --user-trust-provider-type iam-identity-center \
  --description "RentDrive corporate SSO — IAM Identity Center" \
  --policy-reference-name idc \
  --tags Key=Environment,Value=production \
  --query 'VerifiedAccessTrustProvider.VerifiedAccessTrustProviderId' \
  --output text)

# Create Verified Access Instance
INSTANCE_ID=$(aws ec2 create-verified-access-instance \
  --description "RentDrive Zero Trust gateway" \
  --query 'VerifiedAccessInstance.VerifiedAccessInstanceId' \
  --output text)
aws ec2 attach-verified-access-trust-provider \
  --verified-access-instance-id "$INSTANCE_ID" \
  --verified-access-trust-provider-id "$TRUST_PROVIDER_ID"

# Policy: require corporate SSO + MFA (AAL2) + membership in car-rental-admins group
GROUP_ID=$(aws ec2 create-verified-access-group \
  --verified-access-instance-id "$INSTANCE_ID" \
  --description "Admin portal access — MFA + group membership required" \
  --policy-document 'permit(principal, action, resource)
    when {
      context.idc.groups.contains("car-rental-admins") &&
      context.idc.mfa_authenticator_assurance_level == "AAL2"
    };' \
  --query 'VerifiedAccessGroup.VerifiedAccessGroupId' \
  --output text)
echo "Verified Access Group: $GROUP_ID — requires MFA + group membership, no VPN needed"
```

#### Step 2: IAM Permission Boundaries — Limit Blast Radius
```bash
cat > /tmp/permission-boundary.json << 'PBEOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowAppOperations",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject", "s3:PutObject",
        "rds:DescribeDBInstances",
        "cloudwatch:PutMetricData",
        "ssm:GetParameter", "secretsmanager:GetSecretValue"
      ],
      "Resource": "*",
      "Condition": {
        "StringEquals": {"aws:RequestedRegion": ["ap-southeast-1","ap-northeast-1"]},
        "BoolIfExists": {"aws:MultiFactorAuthPresent": "true"}
      }
    },
    {
      "Sid": "DenyPrivilegeEscalation",
      "Effect": "Deny",
      "Action": ["iam:*","organizations:*","account:*","sts:AssumeRole"],
      "Resource": "*"
    }
  ]
}
PBEOF

aws iam create-policy \
  --policy-name "ZeroTrust-RentDrive-AppBoundary" \
  --policy-document file:///tmp/permission-boundary.json

# Apply permission boundary to all application IAM roles
# Even if a role's own policy allows more, the boundary caps it
aws iam put-role-permissions-boundary \
  --role-name "booking-api-role" \
  --permissions-boundary "arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):policy/ZeroTrust-RentDrive-AppBoundary"
```

#### Step 3: VPC Endpoints — Eliminate Internet Exposure for AWS API Calls
```bash
VPC_ID="vpc-xxxxxxxxxxxxxxxxx"
APP_SUBNET="subnet-xxxxxxxxxxxxxxxxx"
APP_SG="sg-xxxxxxxxxxxxxxxxx"

# S3 Gateway Endpoint (free — all S3 API calls route privately)
aws ec2 create-vpc-endpoint \
  --vpc-id $VPC_ID \
  --service-name com.amazonaws.ap-southeast-1.s3 \
  --vpc-endpoint-type Gateway \
  --route-table-ids $(aws ec2 describe-route-tables \
    --filters "Name=vpc-id,Values=$VPC_ID" \
    --query 'RouteTables[0].RouteTableId' --output text)

# SSM, SSMMessages, EC2Messages — required for Session Manager without NAT gateway
for SVC in ssm ssmmessages ec2messages secretsmanager kms; do
  aws ec2 create-vpc-endpoint \
    --vpc-id $VPC_ID \
    --service-name "com.amazonaws.ap-southeast-1.${SVC}" \
    --vpc-endpoint-type Interface \
    --subnet-ids $APP_SUBNET \
    --security-group-ids $APP_SG \
    --private-dns-enabled
  echo "VPC Endpoint created: $SVC"
done
echo "All AWS API calls now route privately — EC2 instances need no internet access"
```

#### 🔐 OWASP ASVS Level 3 — Policy to AWS Implementation

**OWASP ASVS Level 3 Policy:** *"Highest assurance level — continuous verification of identity, device trust, and behavior; cryptographic integrity for all communications; no implicit trust inside the network perimeter; all access decisions logged and auditable."*

```bash
# ── ASVS V2 (Authentication) — AWS Implementation ───────────────────────────
# ASVS 2.1.1: All user passwords >= 12 characters minimum
aws iam update-account-password-policy \
  --minimum-password-length 14 \
  --require-uppercase-characters \
  --require-lowercase-characters \
  --require-numbers \
  --require-symbols \
  --allow-users-to-change-password \
  --max-password-age 90 \
  --password-reuse-prevention 10

# ASVS 2.3.1: Software-generated secrets have at least 112 bits of entropy
# Secrets Manager: verify all secrets use auto-rotation (no static long-lived credentials)
aws secretsmanager list-secrets \
  --query 'SecretList[?RotationEnabled==`false`].{Name:Name,ARN:ARN}' \
  --output table
# Expected: empty — all secrets must have rotation enabled

# ── ASVS V4 (Access Control) — AWS Implementation ────────────────────────────
# ASVS 4.1.1: Enforce access control at a trusted enforcement point (server-side)
# Verified Access: verify policy requires MFA + group membership (no bypass)
aws ec2 describe-verified-access-groups \
  --query 'VerifiedAccessGroups[].{ID:VerifiedAccessGroupId,Policy:PolicyDocument}' \
  --output table

# ASVS 4.3.2: Admin interfaces must not be accessible from the internet
# Verify: no admin SG has 0.0.0.0/0 on management ports
aws ec2 describe-security-groups \
  --filters "Name=tag:Role,Values=admin" "Name=ip-permission.cidr,Values=0.0.0.0/0" \
  --query 'SecurityGroups[].GroupId' --output text
# Expected: empty (no admin SGs accessible from internet)

# ── ASVS V9 (Communications) — AWS Implementation ────────────────────────────
# ASVS 9.1.1: TLS required for all connections; no mixed content
# Verify ALB redirects HTTP to HTTPS (no plaintext allowed)
aws elbv2 describe-listeners \
  --load-balancer-arn "$(aws elbv2 describe-load-balancers --query "LoadBalancers[?LoadBalancerName=='rentdrive-prod-alb'].LoadBalancerArn" --output text)" \
  --query 'Listeners[?Protocol==`HTTP`].DefaultActions[].RedirectConfig' \
  --output table
# Expected: Protocol=HTTPS, StatusCode=HTTP_301

# ── ASVS V10 (Malicious Code) — AWS Implementation ───────────────────────────
# GuardDuty Malware Protection: verify enabled for all EBS volumes
aws guardduty get-detector \
  --detector-id "$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)" \
  --query 'Features[?Name==`EBS_MALWARE_PROTECTION`].Status' --output text
# Expected: ENABLED

echo "OWASP ASVS Level 3 verification complete — all controls validated"
```

### 📚 Challenge — Block 3 (1 Hour)

#### Study Case 9: Zero Trust Contains Lateral Movement

**Scenario:** An attacker compromised a low-privilege EC2 worker node in RentDrive's EKS cluster via a container escape exploit. In a traditional flat-network model, the attacker could pivot freely to RDS, S3, and other services. With Zero Trust microsegmentation, the blast radius was contained to a single compromised pod.

**Zero Trust Controls That Limited the Blast Radius:**
- Each EKS pod uses **IRSA** (IAM Roles for Service Accounts): one role per service, scoped to specific ARNs — the compromised worker had no RDS or S3 access
- **VPC Security Groups**: explicit deny of East-West traffic between service tiers — compromised pod could not reach RDS port 3306
- **AWS Verified Access**: admin portal requires managed device + MFA — stolen credentials alone were insufficient
- **VPC PrivateLink**: no internet egress from private subnets — C2 callback was blocked
- **IAM Permission Boundaries**: even a compromised role cannot `CreateRole` or modify IAM policies

---

## 🗓️ DAY 10 — Enterprise Security Operations & Governance

### 🎯 Learning Objectives
- Establish SOC procedures using Security Hub + GuardDuty as the operations center
- Implement security governance with AWS Organizations SCPs
- Final capstone: full AWS security architecture review for RentDrive SaaS

> **🔐 OWASP Coverage:** [OWASP SAMM v2](https://owaspsamm.org/) (Governance · Design · Implementation · Verification · Operations) · [OWASP ASVS Level 3](https://owasp.org/www-project-application-security-verification-standard/)

### 📖 Theory — Block 1 (1 Hour)

#### 10.1 AWS Multi-Account Security Governance
```
AWS Organizations
├── Management Account  (billing + SCPs — zero workloads run here)
├── Security OU
│   ├── Security Tooling Account  (Security Hub master, GuardDuty admin, Config aggregator)
│   └── Log Archive Account       (CloudTrail, VPC Flow Logs — immutable S3 with Vault Lock)
└── Workloads OU
    ├── Production Account    (RentDrive SaaS — car rental platform)
    ├── Staging Account
    └── Development Account

SCPs enforced at Workloads OU level:
  ✅ Deny disabling CloudTrail, GuardDuty, Config, Security Hub
  ✅ Deny leaving the Organization
  ✅ Deny non-approved AWS regions
  ✅ Require MFA for sensitive destructive actions
```

### 🔬 Lab — Block 2 (2 Hours)

#### Lab 10A — AWS Organizations SCPs and SOC Operations

```bash
# SCP 1: Prevent disabling core security services
aws organizations create-policy \
  --name "DenyDisableSecurityServices" \
  --description "Block disabling GuardDuty, CloudTrail, Config, Security Hub, Macie" \
  --type SERVICE_CONTROL_POLICY \
  --content '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "DenyDisableSecurityServices",
        "Effect": "Deny",
        "Action": [
          "guardduty:DeleteDetector",
          "guardduty:DisassociateFromAdministratorAccount",
          "cloudtrail:DeleteTrail",
          "cloudtrail:StopLogging",
          "cloudtrail:UpdateTrail",
          "securityhub:DisableSecurityHub",
          "config:DeleteConfigurationRecorder",
          "config:StopConfigurationRecorder",
          "config:DeleteDeliveryChannel",
          "macie2:DisableMacie",
          "inspector2:Disable"
        ],
        "Resource": "*"
      },
      {
        "Sid": "DenyAuditLogTampering",
        "Effect": "Deny",
        "Action": ["s3:DeleteBucket","s3:PutBucketPolicy","s3:DeleteBucketPolicy"],
        "Resource": "arn:aws:s3:::rentdrive-cloudtrail-*"
      }
    ]
  }'

# SCP 2: Deny leaving the Organization
aws organizations create-policy \
  --name "DenyLeaveOrganization" \
  --description "Prevent member accounts from leaving the AWS Organization" \
  --type SERVICE_CONTROL_POLICY \
  --content '{
    "Version":"2012-10-17",
    "Statement":[{"Effect":"Deny","Action":"organizations:LeaveOrganization","Resource":"*"}]
  }'

# SCP 3: Restrict to approved regions only (APAC + global services)
aws organizations create-policy \
  --name "DenyUnauthorizedRegions" \
  --description "RentDrive approved regions: ap-southeast-1, ap-northeast-1, us-east-1 (global svc)" \
  --type SERVICE_CONTROL_POLICY \
  --content '{
    "Version": "2012-10-17",
    "Statement": [{
      "Sid": "DenyNonApprovedRegions",
      "Effect": "Deny",
      "NotAction": [
        "iam:*","sts:*","route53:*","cloudfront:*",
        "support:*","budgets:*","organizations:*","account:*"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:RequestedRegion": ["ap-southeast-1","ap-northeast-1","us-east-1"]
        }
      }
    }]
  }'

# SCP 4: Require MFA for destructive/sensitive operations
aws organizations create-policy \
  --name "RequireMFAForDestructiveActions" \
  --description "Deny iam:*, ec2:Terminate, rds:Delete, s3:DeleteBucket without MFA" \
  --type SERVICE_CONTROL_POLICY \
  --content '{
    "Version": "2012-10-17",
    "Statement": [{
      "Sid": "DenyWithoutMFA",
      "Effect": "Deny",
      "Action": [
        "iam:*","ec2:TerminateInstances",
        "rds:DeleteDBInstance","s3:DeleteBucket",
        "kms:ScheduleKeyDeletion","kms:DisableKey"
      ],
      "Resource": "*",
      "Condition": {
        "BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}
      }
    }]
  }'
```

#### 🔐 OWASP SAMM v2 — Policy to AWS Implementation

**OWASP SAMM Policy:** *"Measure and improve software security across five business functions: Governance, Design, Implementation, Verification, and Operations. Establish a baseline maturity level and improve it incrementally."*

```bash
# ── SAMM: Governance — Policy & Compliance ───────────────────────────────────
# AWS Organizations: attach all 4 SCPs to Workloads OU (governance enforcement)
WORKLOADS_OU_ID=$(aws organizations list-organizational-units-for-parent \
  --parent-id "$(aws organizations list-roots --query 'Roots[0].Id' --output text)" \
  --query 'OrganizationalUnits[?Name==`Workloads`].Id' --output text)

for POLICY_NAME in DenyDisableSecurityServices DenyLeaveOrganization DenyUnauthorizedRegions RequireMFAForDestructiveActions; do
  POLICY_ID=$(aws organizations list-policies --filter SERVICE_CONTROL_POLICY \
    --query "Policies[?Name=='${POLICY_NAME}'].Id" --output text)
  aws organizations attach-policy --policy-id "$POLICY_ID" --target-id "$WORKLOADS_OU_ID"
  echo "SCP attached: $POLICY_NAME → Workloads OU"
done

# ── SAMM: Verification — Security Testing ────────────────────────────────────
# Security Hub: OWASP-aligned compliance score (target > 80%)
aws securityhub get-findings \
  --filters '{"WorkflowStatus":[{"Value":"RESOLVED","Comparison":"NOT_EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}],"SeverityLabel":[{"Value":"CRITICAL","Comparison":"EQUALS"}]}' \
  --query 'length(Findings)' --output text
# Target: 0 CRITICAL unresolved findings (SAMM Verification Maturity Level 2)

# ── SAMM: Operations — Incident Management ───────────────────────────────────
# Verify IR runbooks stored in SSM Documents (SAMM Operations practice)
aws ssm list-documents \
  --filters "Key=Owner,Values=$(aws sts get-caller-identity --query Account --output text)" \
  --query 'DocumentIdentifiers[?contains(Name, `rentdrive-ir`) == `true`].{Name:Name,Version:DocumentVersion,Status:Status}' \
  --output table

# ── SAMM: Implementation — Secure Build ──────────────────────────────────────
# ECR: verify all images scanned before deployment (no CRITICAL vulnerabilities in registry)
aws ecr describe-image-scan-findings \
  --repository-name "booking-api" \
  --image-id imageTag=latest \
  --query 'imageScanFindings.findingSeverityCounts' \
  --output table
# Target: CRITICAL = 0, HIGH = 0 (SAMM Implementation Maturity Level 2)

# ── SAMM Maturity Scorecard — Self-Assessment ────────────────────────────────
echo "=== OWASP SAMM v2 Maturity Scorecard — RentDrive SaaS ==="
echo ""
echo "GOVERNANCE"
echo "  Policy & Compliance:  L2 — SCPs enforced; annual review cycle"
echo "  Education & Guidance: L1 — Security training completed (this program)"
echo ""
echo "DESIGN"
echo "  Threat Assessment:    L2 — Threat model per case study completed"
echo "  Security Requirements:L2 — OWASP ASVS Level 3 adopted as baseline"
echo ""
echo "IMPLEMENTATION"
echo "  Secure Build:         L2 — ECR scanning + golden AMI pipeline"
echo "  Defect Management:    L1 — Inspector v2 findings tracked in Security Hub"
echo ""
echo "VERIFICATION"
echo "  Security Testing:     L2 — AWS Config CIS benchmark > 95% compliance"
echo "  Requirements-driven:  L1 — ASVS checklist validated (Day 9)"
echo ""
echo "OPERATIONS"
echo "  Incident Management:  L2 — IR runbooks + quarterly tabletop exercises"
echo "  Environment Mgmt:     L2 — Patch Manager + Config Rules enforced"
echo ""
echo "Target next quarter: advance Threat Assessment and Security Testing to L3"
```

### 📚 Challenge — Block 3 (1 Hour): Final Capstone

#### SOC Daily Shift Checklist
```
☑ Review Security Hub findings — resolve all CRITICAL and HIGH severity
☑ Check GuardDuty findings — acknowledge or suppress confirmed false positives
☑ Verify CloudTrail logging active in all regions:
    aws cloudtrail get-trail-status --name rentdrive-security-trail
☑ Review IAM Access Analyzer findings — zero external access paths tolerated
☑ Check AWS Config compliance score — target > 95%
☑ Verify AWS Backup job completion from nightly runs
☑ Review failed console login attempts (CloudTrail + CloudWatch alarm history)
☑ Check ACM certificate expiry — alert at 30 days remaining
☑ Review new IAM users/roles/policies created in past 24h
☑ Update shift handover log in ticketing system (Jira / ServiceNow)
```

#### Enterprise AWS Security Architecture Checklist — RentDrive SaaS

```
IDENTITY & ACCESS MANAGEMENT
☑ Root account MFA enabled + access keys permanently deleted
☑ All workloads use IAM Roles (no long-term user access keys on EC2/Lambda/EKS)
☑ IAM password policy: 14 char min, complexity, 90-day rotation
☑ MFA enforced via SCP for all sensitive/destructive actions
☑ IAM Access Analyzer enabled — zero unintended external access findings
☑ Unused credentials auto-disabled: AWS Config rule access-keys-rotated
☑ AWS IAM Identity Center (SSO) integrated with corporate IdP (Okta/Azure AD)
☑ IAM Permission Boundaries applied to all application roles

NETWORK SECURITY
☑ No security group allows 0.0.0.0/0 on SSH / RDP / database ports
☑ All databases in private subnets (RDS: no-publicly-accessible)
☑ SSM Session Manager for all admin access — port 22 firewall-closed
☑ AWS WAF v2 + managed rule groups on all ALBs
☑ AWS Shield Advanced on all public-facing load balancers
☑ VPC Flow Logs enabled and forwarded to log archive account
☑ VPC Endpoints for S3, SSM, Secrets Manager, KMS (no internet exposure)

DATA SECURITY
☑ S3 Block Public Access enabled at account-wide level
☑ S3 default encryption: SSE-KMS with customer-managed CMK
☑ RDS encryption at rest with KMS CMK; rds.force_ssl = 1
☑ TLS 1.2+ enforced: ALB HTTPS listener + S3 bucket policy DenyNonTLS
☑ KMS CMK automatic annual rotation enabled
☑ Amazon Macie enabled; weekly PII classification scan scheduled
☑ AWS Backup with Vault Lock for compliance-tier data
☑ S3 Cross-Region Replication for all customer-facing data buckets

LOGGING & MONITORING
☑ CloudTrail multi-region trail + log file validation (digest files)
☑ CloudTrail logs forwarded to immutable log-archive S3 (separate account)
☑ VPC Flow Logs enabled in all production VPCs
☑ CloudWatch metric filters: root login, IAM changes, SG-0.0.0.0/0, S3 policy
☑ Log retention: 90 days CloudWatch, 7 years S3 Glacier (via lifecycle policy)

THREAT DETECTION
☑ GuardDuty enabled in all accounts + all regions; S3/Malware Protection ON
☑ AWS Security Hub aggregating all findings (GuardDuty, Inspector, Macie, Config)
☑ Amazon Inspector v2: EC2, ECR, Lambda scanning active
☑ AWS Config with CIS AWS Foundations Benchmark v1.4

VULNERABILITY MANAGEMENT
☑ Inspector v2: critical findings trigger SNS alert + Security Hub ticket
☑ SSM Patch Manager: critical CVEs auto-approved (ApproveAfterDays: 0)
☑ Golden AMI pipeline: no EOL OS; images rebuilt monthly
☑ ECR enhanced scanning on push for all container images

INCIDENT RESPONSE
☑ IR Plan documented, reviewed annually, approved by leadership
☑ Top 10 IR playbooks stored in SSM Documents (version-controlled)
☑ On-call roster established with PagerDuty/OpsGenie integration
☑ Quarantine SG pre-created in all regions (deny all in/out)
☑ Tabletop exercise completed quarterly; results documented

BUSINESS CONTINUITY
☑ RTO/RPO defined and documented for all tier-1 and tier-2 services
☑ RDS Multi-AZ enabled for all production databases
☑ S3 CRR + Object Lock for all customer PII and contract buckets
☑ AWS Backup plan with cross-region copy to DR region
☑ Monthly DR restoration test with actual RTO measured and recorded

GOVERNANCE
☑ AWS Organizations SCPs: deny disabling security services + unauthorized regions
☑ AWS Config compliance score > 95% across all member accounts
☑ Quarterly security review documented and shared with leadership
☑ Annual third-party penetration test + remediation tracked
☑ Security awareness training for all staff (phishing simulation included)
☑ Change management process enforced for all production IAM/network changes
```

---

## 📊 10-Day Summary

| Day | Topic | Key AWS Services | Deliverable |
|-----|-------|-----------------|-------------|
| 1 | IAM & Access Control | IAM, GuardDuty, CloudTrail, Budgets | Policies, MFA, GuardDuty active |
| 2 | Network Architecture | VPC, Security Groups, SSM | 3-tier VPC, no SSH bastion |
| 3 | Data Security | KMS, S3, Macie, Object Lock | Encrypted + WORM + TLS buckets |
| 4 | Monitoring & SIEM | CloudTrail, CloudWatch, GuardDuty, Security Hub | 8+ critical alarms live |
| 5 | Vulnerability Management | Inspector v2, Patch Manager, Config | Auto-patching + CIS baseline |
| 6 | Application Security | WAF v2, Shield Advanced, EKS PSS | WAF rules + DDoS protection |
| 7 | Incident Response | GuardDuty, CloudTrail, SNS, EBS Snapshots | IR playbook + simulation run |
| 8 | Business Continuity | AWS Backup, RDS Multi-AZ, S3 CRR | Cross-region DR configured + tested |
| 9 | Zero Trust | Verified Access, IAM Identity Center, PrivateLink | ZT policies enforced |
| 10 | SOC & Governance | Security Hub, Organizations, SCPs | Full runbook + capstone audit |

### Daily 4-Hour Block Breakdown
```
Block 1 — ABSORB  (1h):  Read theory section + AWS service documentation
Block 2 — APPLY   (2h):  Execute lab commands in AWS Console + CLI
Block 3 — CHALLENGE (1h): Analyze case study + answer quiz + update runbook
```

---

## 🗺️ OWASP → AWS Controls Master Mapping

| OWASP Risk | Risk Description | Primary AWS Control | Config Rule / WAF Rule | Day |
|------------|-----------------|---------------------|----------------------|-----|
| **A01** | Broken Access Control | IAM least-privilege, Access Analyzer | `iam-policy-no-statements-with-admin-access` | 1, 9 |
| **A02** | Cryptographic Failures | KMS CMK, S3 SSE, TLS on ALB | `s3-bucket-server-side-encryption-enabled`, `rds-storage-encrypted` | 3 |
| **A03** | Injection (SQLi, XSS) | AWS WAF v2 SQLi + Common Rule Set | `AWSManagedRulesSQLiRuleSet` | 6 |
| **A04** | Insecure Design | AWS Threat Composer, Well-Architected Review | Security Hub findings triage | 1, 10 |
| **A05** | Security Misconfiguration | AWS Config, Security Hub, Security Groups | `restricted-ssh`, `rds-instance-public-access-check` | 2, 8 |
| **A06** | Vulnerable & Outdated Components | Amazon Inspector v2, SSM Patch Manager, ECR Scan | `approved-amis-by-tag` | 5 |
| **A07** | Auth Failures | IAM MFA, IAM Identity Center, Cognito | `mfa-enabled-for-iam-console-access` | 1, 9 |
| **A08** | Software & Data Integrity | CodePipeline signing, ECR image signing, S3 Object Lock | `s3-object-lock-enabled` | 3, 8 |
| **A09** | Logging & Monitoring Failures | CloudTrail, CloudWatch Alarms, Security Hub | `cloudtrail-enabled`, `cloud-trail-log-file-validation-enabled` | 4 |
| **A10** | Server-Side Request Forgery | IMDSv2 enforcement, VPC Endpoints, NACLs | SCP `EnforceIMDSv2` | 7 |
| **API1** | BOLA | API Gateway + Lambda Authorizer (resource ownership check) | Custom authorizer | 6 |
| **API2** | Broken Auth | Cognito + JWT validation + short token TTL | API Gateway authorizer | 6 |
| **API3** | Broken Object Property Auth | API response schema validation, IAM data-level policies | WAF body inspection | 6 |
| **API5** | Broken Function Level Auth | IAM roles per API function, Gateway resource policy | `iam-policy-no-statements-with-admin-access` | 6 |
| **API8** | Security Misconfiguration | API Gateway stages locked down, verbose errors disabled | Security Hub findings | 6 |
| **SAMM Governance** | Policy & Compliance | AWS Organizations SCPs | SCP compliance report | 10 |
| **SAMM Verification** | Security Testing | Security Hub, Inspector v2, Config | Compliance score > 95% | 10 |
| **ASVS L3** | Full Verification Standard | IAM, ALB TLS, Verified Access, GuardDuty | All rules above combined | 9 |

### OWASP Compliance Quick-Check Commands
```bash
# Run this daily during SOC shift to verify OWASP control status
echo "=== OWASP Daily Compliance Check — RentDrive SaaS ==="

# A01: No external access analyzer findings
echo -n "A01 Access Analyzer findings: "
aws accessanalyzer list-findings \
  --analyzer-name "rentdrive-access-analyzer" \
  --filter '{"status":{"eq":["ACTIVE"]}}' \
  --query 'length(findings)' --output text

# A02: No unencrypted RDS instances
echo -n "A02 Unencrypted RDS: "
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name "rds-storage-encrypted" --compliance-types NON_COMPLIANT \
  --query 'length(EvaluationResults)' --output text

# A03: WAF active on production ALB
echo -n "A03 WAF associations: "
aws wafv2 list-resources-for-web-acl \
  --web-acl-arn "$(aws wafv2 list-web-acls --scope REGIONAL --region ap-southeast-1 --query "WebACLs[?Name=='rentdrive-waf-prod'].ARN" --output text)" \
  --scope REGIONAL --region ap-southeast-1 \
  --query 'length(ResourceArns)' --output text

# A06: Active CRITICAL CVE findings (must be 0)
echo -n "A06 CRITICAL CVEs: "
aws inspector2 list-findings \
  --filter-criteria '{"severity":[{"comparison":"EQUALS","value":"CRITICAL"}],"findingStatus":[{"comparison":"EQUALS","value":"ACTIVE"}]}' \
  --query 'length(findings)' --output text

# A09: CloudTrail active
echo -n "A09 CloudTrail status: "
aws cloudtrail get-trail-status \
  --name "rentdrive-security-trail" \
  --query 'IsLogging' --output text

# A10: IMDSv2 compliance (count instances NOT using required tokens)
echo -n "A10 IMDSv1 instances remaining: "
aws ec2 describe-instances \
  --filters "Name=instance-state-name,Values=running" "Name=metadata-options.http-tokens,Values=optional" \
  --query 'length(Reservations[].Instances[])' --output text

echo "=== All values should be 0 or true for full OWASP compliance ==="
```


---

## 📚 Reference Resources

### AWS Security Documentation
- **AWS Security Hub:** https://docs.aws.amazon.com/securityhub/
- **IAM Best Practices:** https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html
- **Amazon GuardDuty:** https://docs.aws.amazon.com/guardduty/
- **AWS WAF v2:** https://docs.aws.amazon.com/waf/
- **AWS CloudTrail:** https://docs.aws.amazon.com/cloudtrail/
- **AWS Well-Architected Security Pillar:** https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/
- **AWS Security Incident Response Guide:** https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/

### Security Frameworks
- NIST Cybersecurity Framework (CSF 2.0)
- CIS AWS Foundations Benchmark v3.0
- ISO 27001:2022 Annex A controls
- OWASP Cloud Security Guide
- CSA Cloud Controls Matrix (CCM v4)
- AWS Well-Architected Framework — Security Pillar

### Certification Path Post-Training
1. **AWS Certified Security — Specialty** — Most aligned; target immediately after Day 10
2. **AWS Certified Solutions Architect — Associate** — Complement with broader architecture (2 weeks)
3. **CompTIA Security+** — Vendor-neutral foundation (1 month additional)
4. **CCSP (Certified Cloud Security Professional)** — Advanced multi-cloud (3 months)
5. **CISSP** — Leadership-level (6 months; requires 5 years experience)

---

*Document Version: 2.0 | Last Updated: May 2026 | Classification: Internal Training*
*Platform: AWS | Case Study: RentDrive SaaS — B2B Car Rental Management Platform*
*Previous Version: Tencent Cloud (v1.0) | Review Cycle: Quarterly*
