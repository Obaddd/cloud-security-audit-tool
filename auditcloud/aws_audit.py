import boto3
from botocore.exceptions import ClientError
from auditcloud.iam_audit import run_iam_audit

PUBLIC_URIS = {
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
}

def run_aws_audit():
    s3 = boto3.client("s3")

    findings = []
    summary = {
        "buckets_scanned": 0,
        "public_buckets": 0,
        "public_access_block_missing_or_weak": 0,
        "public_acl_grants": 0,
        "public_policy_buckets": 0,
    }

    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except ClientError as e:
        return {"error": str(e)}

    for b in buckets:
        name = b["Name"]
        summary["buckets_scanned"] += 1

        bucket_is_public = False

        # 1) Public Access Block (PAB)
        try:
            pab = s3.get_public_access_block(Bucket=name)
            cfg = pab.get("PublicAccessBlockConfiguration", {})
            required = ["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"]
            weak = [k for k in required if cfg.get(k) is not True]
            if weak:
                summary["public_access_block_missing_or_weak"] += 1
                findings.append({
                    "severity": "MEDIUM",
                    "service": "s3",
                    "resource": name,
                    "issue": f"PublicAccessBlock not fully enforced: {', '.join(weak)}"
                })
        except ClientError:
            summary["public_access_block_missing_or_weak"] += 1
            findings.append({
                "severity": "MEDIUM",
                "service": "s3",
                "resource": name,
                "issue": "PublicAccessBlock is missing or not readable with current permissions"
            })

        # 2) Bucket policy status (public?)
        try:
            status = s3.get_bucket_policy_status(Bucket=name)
            is_public = status["PolicyStatus"].get("IsPublic", False)
            if is_public:
                summary["public_policy_buckets"] += 1
                bucket_is_public = True
                findings.append({
                    "severity": "HIGH",
                    "service": "s3",
                    "resource": name,
                    "issue": "Bucket policy indicates bucket is public"
                })
        except ClientError:
            pass

        # 3) ACL public grants
        try:
            acl = s3.get_bucket_acl(Bucket=name)
            for g in acl.get("Grants", []):
                grantee = g.get("Grantee", {})
                uri = grantee.get("URI", "")
                if uri in PUBLIC_URIS:
                    summary["public_acl_grants"] += 1
                    bucket_is_public = True
                    findings.append({
                        "severity": "HIGH",
                        "service": "s3",
                        "resource": name,
                        "issue": f"Bucket ACL grants {g.get('Permission')} to public group ({uri})"
                    })
        except ClientError:
            pass

        if bucket_is_public:
            summary["public_buckets"] += 1

        return {
        "summary": summary,
        "findings": findings,
        "iam": run_iam_audit()
    }