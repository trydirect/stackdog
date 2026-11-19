# Security update - NGINX2Root (CVE-2026-123007): update your trydirect/nginx image and install Stackdog

**Severity:** Critical (CVSS 9.2) · **Disclosed:** 18 Nov 2026 · **Action required**

> **TL;DR** - A critical, remotely exploitable nginx bug (CVE-2026-123007) is public.
> Update your `trydirect/nginx` image and **restart** your containers (a reload is
> not enough), then install Stackdog to keep watching for it and for other recent
> vulnerabilities such as PHP2Shell.

---

## What happened

On **18 November 2026**, five memory-corruption vulnerabilities in nginx - together
called **NGINX2Root** - were disclosed. The worst, **CVE-2026-123007**, is
**unauthenticated remote code execution over HTTP/2**: anyone who can reach a
server with HTTP/2 enabled can run commands as the nginx worker, with no
application bug required. A public proof-of-concept exists. A separate, still
**unpatched** Linux kernel bug can then escalate that access to **root**,
including escaping a Docker container onto the host.

This affects any nginx reachable directly from the internet - including static
sites. The fixed releases are **nginx 1.30.7 (stable)** and **1.31.9 (mainline)**
(NGINX Plus 37.0.8.1 / 37.3.0.1).

⚠️ **A configuration reload does _not_ fix this.** `nginx -s reload` keeps the old,
vulnerable binary answering. You must restart the process or re-create the
container.

We've released an updated **`trydirect/nginx`** image that carries the fix.

> **Reminder for users of the image** - Per the NGINX2Root advisory, containers
> must be **re-created**, not reloaded: `docker compose up -d --force-recreate`.
> `nginx -s reload` keeps the vulnerable binary running. This applies to
> **everyone running `trydirect/nginx`**, including platform or compose stacks
> that pin `:latest` - make sure those pull the fixed image and re-create too.

---

## 1 - Update your `trydirect/nginx` image

The updated images carry **nginx 1.31.9** (the fixed release). Re-create your
containers so they run it - a reload keeps the vulnerable binary. Two ways to do
it:

**Using the trydirect status panel agent?** If the deployment is managed by the
platform, roll it out with one command:

```bash
stacker agent deploy-app <app-code> --image trydirect/nginx:latest --force
```

This pulls the fixed image and re-creates the container automatically (not a
reload), and fails loudly if the image cannot be applied instead of silently
running the old one.

**Or manually with docker.** Pull the fixed image and **re-create** your
containers (do not keep running the old one):

```bash
# Pull the fixed image
docker pull trydirect/nginx:latest     # or your pinned tag, e.g. trydirect/nginx:<new-version>

# docker compose
docker compose pull nginx
docker compose up -d --force-recreate nginx

# docker run
docker stop <nginx-container> && docker rm <nginx-container>
docker run -d ... trydirect/nginx:latest
```

Confirm the running build is fixed:

```bash
docker exec <nginx-container> nginx -v
# expect 1.31.9 or later (the updated trydirect/nginx ships 1.31.9). Distro
# builds may show an older upstream number while carrying a backported fix.
```

**If you can't update right now**, turn the affected features off as a stopgap and
restart:

```nginx
http2 off;      # CVE-2026-123007 / CVE-2026-123633 - or drop "http2" from listen
# remove quic/http3 listeners            # CVE-2026-121810
# point proxy_pass at a fixed upstream   # CVE-2026-123634 (no variables + SSI/mirror)
# restrict mail listeners to trusted IPs # CVE-2026-113425
```

On hosts that don't need SCTP, block the kernel escalation step too:

```bash
echo 'install sctp /bin/false' | sudo tee /etc/modprobe.d/zz-block-sctp.conf
sudo rmmod sctp 2>/dev/null || true
```

---

## 2 - Install Stackdog for ongoing protection

Stackdog is a lightweight security agent for Linux hosts and Docker containers -
real-time threat detection and response (a modern fail2ban, plus container and
host monitoring). One command to install:

```bash
curl -fsSL https://raw.githubusercontent.com/trydirect/stackdog/main/install.sh | sudo bash
```

Stackdog watches for **NGINX2Root** and other recent vulnerabilities:

| Threat | What Stackdog does |
|---|---|
| **NGINX2Root** (CVE-2026-123007 + 4 more) | Flags exposed nginx builds and the exact config that reaches each CVE (HTTP/2, HTTP/3, mail proxy, resolver) on the host and in containers; alerts on the worker-crash spray and on **any command run by an nginx worker** (the RCE tell); warns when the kernel SCTP escalation step is reachable. |
| **PHP2Shell** (CVE-2026-109618 / 109619) | Detects exposed PHP builds, PHP worker crashes, and the exploit footprint - and bans the clients driving it. |
| **SSHole** (CVE-2026-123158) | Flags vulnerable OpenSSH builds and bans password logins to key-only accounts. |
| **Everything else** (`vuln.cve-watch`) | Continuously matches every installed package on the host **and in containers** against OSV and CISA's known-exploited catalog. |

It also does fail2ban-style IP bans, container quarantine, file-integrity
monitoring, and webshell detection. It **detects and responds** - it does not
patch, so keep your images updated.

---

## How to tell if you were already hit

The attack is deliberately quiet (its HTTP/2 control frames are never logged), so
look for the aftermath:

- **Programs started by the nginx worker** - workers serve requests, they don't
  run programs. Anything spawned by one is a strong sign of compromise:
  ```bash
  ps -u www-data -o pid,ppid,lstart,cmd     # or your nginx user
  ```
- **Runs of nginx workers dying on memory faults** (signal 11 / SIGSEGV):
  ```bash
  sudo journalctl -u nginx --since "-24h" | grep -iE 'signal 11|segfault|worker process'
  ```
- **Loaded SCTP kernel module** (the root-escalation path):
  ```bash
  grep sctp /proc/modules
  ```

If you see any of these, treat the host/container as compromised: isolate it,
rotate secrets, and investigate before bringing it back.

---

## Summary

1. **Update `trydirect/nginx`** and **re-create** your containers (with the
   status panel agent's `deploy-app`, or manually) - a reload does not fix this.
2. **Install Stackdog** to continuously detect NGINX2Root, PHP2Shell, SSHole and
   other vulnerabilities across your hosts and containers.
3. **Check the IOCs** above if you think you may have been exposed.

Questions? See the full write-up on the Stackdog blog
(**CVE-2026-123007: NGINX2Root and how to protect your servers and containers**)
or reach out to the trydirect team.

---

*Fill-in notes for the sender: confirm the exact `trydirect/nginx` tag to pull
(`:latest` vs a versioned tag) and the container/service names in the compose
examples to match how your users deploy it. The Stackdog install command and the
CVE facts are final.*
