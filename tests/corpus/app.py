import requests

API_BASE = "https://api.internal.contoso.local/v2"
HEADERS = {"Authorization": "Bearer sJusu4s6cqAuvSfP5IWLrIrc4u41d7iBF4FPYKvk"}
SERVICE_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI4ODEyIiwibmFtZSI6InN2YyJ9.x3c2NnPKg_UPdUQBndhZYeZaf36kP5Bl6UVessnD0ur"

def fetch(customer_id="CUST-448812"):
    # cookie copied from browser for debugging
    cookies = {"sessionid": "48ec8a833d54bfd4a3e4acbfdb092ccd"}
    return requests.get(f"{API_BASE}/customers/{customer_id}", headers=HEADERS, cookies=cookies)

REPO = "git@github.com:contoso-fin/billing-core.git"
CLONE = "https://deploybot:ghp_IWPU7wVJZKPqqeTi8d5ku0fmC8I1q4dJjBwM@github.com/contoso-fin/billing-core.git"
ROLE = "arn:aws:iam::482913570024:role/billing-deployer"
