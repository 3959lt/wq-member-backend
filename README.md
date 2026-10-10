# WQ Member Backend 0.5.0

Membership administration and authenticated VMess forwarding with Xray. Each ordinary user has an independent UUID. Membership expiry, account disabling, subscription disabling and cumulative traffic quotas are synchronized to the actual node. Mihomo compatibility has been tested.

## Run the web application

```sh
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Edit .env with a strong initial password and random secret.
set -a
source .env
set +a
gunicorn --workers 2 --bind 127.0.0.1:8000 app:app
```

Public deployment requires HTTPS and COOKIE_SECURE=1. The deployed systemd example currently binds 0.0.0.0:8000 for preview. Remove ADMIN_PASSWORD from the environment after initial setup.

## Network node

See [network setup and operations](network/README.md). The network agent requires an installed Xray binary, a configured net_settings database row, dedicated service users and limited sudo authorization. Service definitions alone are not a complete fresh-server installation script. The VMess node listens on TCP 443; its StatsService API binds only to 127.0.0.1:10085.

Administrators can grant days, revoke authorization, rotate node credentials and set a cumulative quota. Users generate a subscription link and import it into Mihomo. Quota is lifetime cumulative and is not reset by renewal. Synchronization and traffic sampling run approximately every 15 seconds. Authorization changes restart the node and briefly interrupt all connections.

## Tests

```sh
python test_app.py
```

Tests use a temporary database. Deployment verification covered actual Xray and Mihomo forwarding, per-user traffic recording, metadata-address blocking and rejection after membership expiry. No live credentials or databases are included.

## Limits

Payment confirmation remains manual. Email verification, password recovery, strict device limits and per-user rate limiting are not implemented. Traffic accounting is approximate and may lose the final sampling interval after a node crash. Configure secure HTTPS subscription distribution, monitoring, load testing and off-server backups before production use.

## Domain routing

Subscriptions now export rule mode, service category selectors and domain/IP routing. Admins edit priority rules and category defaults on `/admin/routing`. See [routing guide](分流规则说明.md). Clients must refresh subscriptions and select rule mode.

## Alipay collection QR

Order checkout supports a privately configured Alipay collection QR with manual receipt confirmation. The payment page refreshes internal order status; it does not query Alipay or automatically confirm payments. See [setup](支付宝收款说明.md).
