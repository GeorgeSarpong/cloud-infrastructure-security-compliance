# Cloud Infrastructure Security & Compliance

![AWS Security](https://img.shields.io/badge/AWS-Security%20Hub-orange)
![Azure Security](https://img.shields.io/badge/Azure-Defender%20for%20Cloud-blue)
![SOC2](https://img.shields.io/badge/Compliance-SOC2-green)
![NIST](https://img.shields.io/badge/Framework-NIST%20CSF-green)
![IAM](https://img.shields.io/badge/Tool-IAM%20%26%20RBAC-orange)
![KMS](https://img.shields.io/badge/Tool-KMS%20Encryption-orange)

---

## Project Overview

This project implements comprehensive cloud infrastructure security and compliance controls across AWS and Azure — covering IAM policies, VPC security, KMS encryption, SOC2 and NIST compliance frameworks, threat detection, and automated security scanning.

Built to demonstrate operational readiness for:
- Cloud Infrastructure Engineer roles
- Cloud Security Engineer roles
- DevSecOps Engineer roles
- Compliance Engineer roles

---

## Security Architecture Overview

---

## IAM Security Implementation

### AWS IAM Least Privilege Policy

```hcl
# Terraform — IAM policy with least privilege
resource "aws_iam_policy" "app_policy" {
  name        = "app-least-privilege-policy"
  description = "Least privilege policy for application role"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "S3ReadAccess"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::${var.app_bucket}",
          "arn:aws:s3:::${var.app_bucket}/*"
        ]
      },
      {
        Sid    = "DynamoDBAccess"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
          "dynamodb:Query"
        ]
        Resource = "arn:aws:dynamodb:*:*:table/${var.table_name}"
      },
      {
        Sid    = "DenyAll"
        Effect = "Deny"
        Action = [
          "iam:*",
          "organizations:*",
          "account:*"
        ]
        Resource = "*"
      }
    ]
  })
}

# IAM Role with trust policy
resource "aws_iam_role" "app_role" {
  name = "app-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Condition = {
          StringEquals = {
            "aws:RequestedRegion" = "us-east-1"
          }
        }
      }
    ]
  })

  tags = {
    Name        = "app-execution-role"
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}
```

---

##  VPC Security Configuration

```hcl
# Security Group — Web Tier
resource "aws_security_group" "web_tier" {
  name        = "web-tier-sg"
  description = "Security group for web tier — allows HTTPS only"
  vpc_id      = var.vpc_id

  ingress {
    description = "HTTPS from anywhere"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTP redirect"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "web-tier-sg"
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}

# Security Group — App Tier (no direct internet access)
resource "aws_security_group" "app_tier" {
  name        = "app-tier-sg"
  description = "Security group for app tier — allows from web tier only"
  vpc_id      = var.vpc_id

  ingress {
    description     = "From web tier only"
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.web_tier.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "app-tier-sg"
  }
}
```

---

## KMS Encryption Implementation

```hcl
# KMS Key with rotation
resource "aws_kms_key" "main" {
  description             = "Main KMS key for data encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  multi_region            = false

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${var.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow key usage for application"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.app_role.arn
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name        = "main-encryption-key"
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}
```

---

## AWS Security Hub & GuardDuty

```hcl
# Enable Security Hub
resource "aws_securityhub_account" "main" {}

# Enable CIS AWS Foundations standard
resource "aws_securityhub_standards_subscription" "cis" {
  depends_on    = [aws_securityhub_account.main]
  standards_arn = "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0"
}

# Enable AWS Foundational Security Best Practices
resource "aws_securityhub_standards_subscription" "aws_foundations" {
  depends_on    = [aws_securityhub_account.main]
  standards_arn = "arn:aws:securityhub:us-east-1::standards/aws-foundational-security-best-practices/v/1.0.0"
}

# Enable GuardDuty
resource "aws_guardduty_detector" "main" {
  enable = true

  datasources {
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = true
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = true
        }
      }
    }
  }

  tags = {
    Name        = "guardduty-detector"
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}
```

---

## SOC2 Controls Implementation

| Control | Category | Implementation |
|---|---|---|
| CC6.1 | Logical Access | IAM least privilege policies |
| CC6.2 | Authentication | MFA enforcement for all users |
| CC6.3 | Authorization | RBAC with IAM roles |
| CC6.6 | Network Controls | VPC security groups and NACLs |
| CC6.7 | Encryption | KMS encryption at rest and in transit |
| CC7.1 | Monitoring | CloudWatch and Security Hub |
| CC7.2 | Vulnerability Management | AWS Inspector and GuardDuty |
| CC8.1 | Change Management | Terraform IaC with CI/CD |
| A1.1 | Availability | Multi-AZ deployments |
| A1.2 | Recovery | RDS automated backups |

---

## Automated Security Scanning

```yaml
# GitHub Actions — Security Scanning Pipeline
name: Security Compliance Scan

on:
  push:
    branches: [main]
  schedule:
    - cron: '0 6 * * *'  # Daily scan at 6am

jobs:
  terraform-security-scan:
    name: Terraform Security Scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Run tfsec
        uses: aquasecurity/tfsec-action@v1.0.0
        with:
          soft_fail: false

      - name: Run Checkov
        uses: bridgecrewio/checkov-action@master
        with:
          directory: .
          framework: terraform
          soft_fail: false

  container-security-scan:
    name: Container Security Scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Run Trivy filesystem scan
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: fs
          scan-ref: .
          severity: CRITICAL,HIGH
          exit-code: 1

  compliance-check:
    name: Compliance Check
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Run AWS Config rules check
        run: python scripts/check_compliance.py
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
```

---

## NIST CSF Framework Implementation

| Function | Category | Controls Implemented |
|---|---|---|
| Identify | Asset Management | AWS Config, resource tagging |
| Protect | Access Control | IAM, MFA, least privilege |
| Protect | Data Security | KMS, S3 encryption, TLS |
| Detect | Anomalies | GuardDuty, Security Hub |
| Detect | Monitoring | CloudWatch, CloudTrail |
| Respond | Response Planning | Incident runbooks |
| Recover | Recovery Planning | Backup and DR procedures |

---

## Security Incident Response Runbook

```markdown
### Phase 1 — Detection
1. Security Hub finding or GuardDuty alert fires
2. Acknowledge alert in security dashboard
3. Create P1 incident ticket immediately
4. Notify security on-call team

### Phase 2 — Containment
1. Identify compromised resource
2. Isolate affected instance — remove from load balancer
3. Revoke compromised IAM credentials immediately
4. Block malicious IP in security group
5. Preserve evidence — snapshot EBS volumes

### Phase 3 — Eradication
1. Terminate compromised instances
2. Rotate all potentially exposed credentials
3. Patch vulnerability that was exploited
4. Deploy clean replacement infrastructure

### Phase 4 — Recovery
1. Deploy new clean infrastructure from IaC
2. Restore from last known good backup
3. Verify no persistence mechanisms remain
4. Monitor for 48 hours post-recovery

### Phase 5 — Post-Incident
1. Complete incident report within 24 hours
2. Root cause analysis within 48 hours
3. Update security controls to prevent recurrence
4. Brief stakeholders on findings
```

---

##  Author

**George Amankwaa Sarpong**
Cloud Infrastructure Engineer | Cloud Security & Compliance
📍 Accra, Ghana
🔗 [LinkedIn](https://linkedin.com/in/georgesarpong)
🌐 [GitHub Portfolio](https://github.com/GeorgeSarpong)

---

*This project is part of a broader portfolio demonstrating readiness for Cloud Infrastructure Engineer roles in the US market.*
