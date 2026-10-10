# WQ Member Backend

Membership, manual billing, node inventory and Clash/Mihomo subscription management.

## Run locally

```sh
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Edit .env: use a random secret and strong initial password
set -a
source .env
set +a
gunicorn --workers 2 --bind 127.0.0.1:8000 app:app
```

Remove ADMIN_PASSWORD after first initialization. Public deployment requires HTTPS and COOKIE_SECURE=1.

## Tests

`python test_app.py` uses a temporary database.

## Deployment

Systemd examples use a dedicated wqbackend account, /opt/wq-backend, /etc/wq-backend.env and /var/lib/wq-backend. Create the account, virtual environment and directories with appropriate permissions before enabling services. Backups retain seven copies; configure off-server backups for production.

## Limitations

No live payment gateway, proxy provisioning, node credential synchronization or traffic metering is included. Subscription expiration and token rotation prevent future downloads but do not revoke credentials already downloaded. Administrators must provision unique user credentials on actual nodes. YAML export uses only the proxies list and generates a selector and MATCH rule. Email verification and password recovery are not implemented.

No production credentials, database or user configurations are included.

## Login fixes in 0.2.0

- Dedicated `wq_member_session` cookie avoids collisions with other localhost Flask applications.
- Only failed logins consume the login limit. Account and IP limits are separate, so users sharing an SSH tunnel do not share one account limit.
- Invalid login/registration CSRF tokens return to a fresh form without authenticating the request.
- Administrator initialization uses a database write transaction to prevent concurrent-worker races.
- The health endpoint identifies the service and version.

For SSH preview, use one consistent browser hostname. If a tab was open during deployment, refresh the login form. Public-IP access requires separate HTTPS and reverse-proxy deployment; the systemd service now binds 0.0.0.0:8000; the local-run example remains localhost-only.

## Public listener

The systemd service listens on `0.0.0.0:8000`. Use the instance public IP with port 8000 in the browser. EC2 security groups must allow the port from the intended source IPs. Direct HTTP access is not encrypted; configure HTTPS before customer use.
