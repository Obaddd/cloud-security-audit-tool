import boto3
from botocore.exceptions import ClientError

DANGEROUS_ACTIONS = {
    "iam:PassRole",
    "sts:AssumeRole",
    "kms:Decrypt",
    "organizations:*",
    "iam:*",
    "s3:*",
    "*:*",
}

def _to_list(x):
    if x is None:
        return []
    if isinstance(x, list):
        return x
    return [x]

def run_iam_audit():
    iam = boto3.client("iam")

    findings = []
    summary = {"policies_checked": 0, "high_risk_policies": 0}

    try:
        policies = iam.list_policies(Scope="Local").get("Policies", [])
    except ClientError as e:
        return {"error": str(e)}

    for p in policies:
        arn = p["Arn"]
        name = p["PolicyName"]
        summary["policies_checked"] += 1

        try:
            default_ver = iam.get_policy(PolicyArn=arn)["Policy"]["DefaultVersionId"]
            doc = iam.get_policy_version(PolicyArn=arn, VersionId=default_ver)["PolicyVersion"]["Document"]
        except ClientError:
            continue

        statements = doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for st in statements:
            if st.get("Effect") != "Allow":
                continue

            actions = set(_to_list(st.get("Action")))
            resources = set(_to_list(st.get("Resource")))

            # Admin-like wildcard action
            if "*" in actions or "*:*" in actions:
                findings.append({
                    "severity": "HIGH",
                    "service": "iam",
                    "resource": name,
                    "issue": "Policy allows wildcard Action (admin-like permissions).",
                    "details": {"policy_arn": arn}
                })
                summary["high_risk_policies"] += 1
                break

            # Dangerous actions + Resource="*"
            if "*" in resources:
                if any(a in actions for a in DANGEROUS_ACTIONS):
                    findings.append({
                        "severity": "HIGH",
                        "service": "iam",
                        "resource": name,
                        "issue": "Dangerous IAM actions allowed with Resource='*'.",
                        "details": {
                            "policy_arn": arn,
                            "actions_sample": sorted(list(actions))[:20]
                        }
                    })
                    summary["high_risk_policies"] += 1
                    break

    return {"summary": summary, "findings": findings}