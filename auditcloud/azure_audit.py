from azure.identity import DefaultAzureCredential
from azure.mgmt.storage import StorageManagementClient
from azure.storage.blob import BlobServiceClient

def run_azure_audit(subscription_id: str):
    cred = DefaultAzureCredential(exclude_interactive_browser_credential=False)
    smc = StorageManagementClient(cred, subscription_id)

    findings = []
    summary = {
        "storage_accounts_scanned": 0,
        "containers_scanned": 0,
        "public_storage_accounts": 0,
        "public_containers": 0,
        "data_plane_scan_failures": 0,
    }

    for acct in smc.storage_accounts.list():
        summary["storage_accounts_scanned"] += 1
        name = acct.name
        rg = acct.id.split("/resourceGroups/")[1].split("/")[0]
        resource = f"{rg}/{name}"

        props = smc.storage_accounts.get_properties(rg, name)
        allow_public = getattr(props, "allow_blob_public_access", None)

        if allow_public is True:
            summary["public_storage_accounts"] += 1
            findings.append({
                "severity": "HIGH",
                "service": "azure-blob",
                "resource": resource,
                "issue": "Storage account allows blob public access (allowBlobPublicAccess=true)."
            })

        # Try listing containers (requires RBAC: Storage Blob Data Reader on the account)
        try:
            bsc = BlobServiceClient(account_url=f"https://{name}.blob.core.windows.net", credential=cred)
            for c in bsc.list_containers():
                summary["containers_scanned"] += 1
                if c.public_access in ("blob", "container"):
                    summary["public_containers"] += 1
                    findings.append({
                        "severity": "HIGH",
                        "service": "azure-blob",
                        "resource": f"{resource}/{c.name}",
                        "issue": f"Blob container is publicly accessible (public_access={c.public_access})."
                    })
        except Exception:
            summary["data_plane_scan_failures"] += 1
            findings.append({
                "severity": "MEDIUM",
                "service": "azure-blob",
                "resource": resource,
                "issue": "Could not enumerate containers (missing Storage Blob Data Reader or data-plane access)."
            })

    return {"summary": summary, "findings": findings}