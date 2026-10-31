import type { Metadata } from 'next';
import Link from 'next/link';
import { ArrowRight, ShieldAlert } from 'lucide-react';
import CopyButton from '@/components/CopyButton';
import { getSiteUrl } from '@/lib/config';
import { buildDocsStructuredData, toJsonLd } from '@/lib/structured-data';

const PAGE_PATH = '/php-shell-quickstart';

const installCommand =
  'curl -fsSL https://raw.githubusercontent.com/trydirect/stackdog/main/install.sh | sudo bash';

const envCommand = `sudo install -d -m 700 /etc/stackdog /var/lib/stackdog
sudo tee /etc/stackdog/stackdog.env > /dev/null <<'EOF'
# API and dashboard backend: this machine only
APP_HOST=127.0.0.1
APP_PORT=5000
DATABASE_URL=/var/lib/stackdog/stackdog.db

# PHP shell detection
STACKDOG_PHPSHELL_ENABLED=true
STACKDOG_PHPSHELL_PATHS=/var/www
# PHP2Shell: alert on PHP builds older than the fixed releases
STACKDOG_PHP_VERSION_CHECK_ENABLED=true
# Access logs the bans are read from, and PHP error logs for worker crashes.
# Paths that do not exist are skipped.
STACKDOG_LOG_SOURCES=/var/log/nginx/access.log,/var/log/apache2/access.log,/var/log/httpd/access_log,/var/log/apache2/error.log,/var/log/nginx/error.log,/var/log/php8.3-fpm.log

# Bans: 5 offenses in 5 minutes, banned for 30 minutes
STACKDOG_IP_BAN_ENABLED=true
STACKDOG_IP_BAN_MAX_RETRIES=5
STACKDOG_IP_BAN_FIND_TIME_SECS=300
STACKDOG_IP_BAN_BAN_TIME_SECS=1800
STACKDOG_IP_BAN_MAX_PER_MINUTE=10
STACKDOG_IP_BAN_PROTECT_LOCAL_IPS=true
# Ban on deterministic detectors only, not on free-text analyzer findings
STACKDOG_IP_BAN_FROM_AI_FINDINGS=false
# Never ban these: your office or VPN, uptime checks, load balancer, CDN
STACKDOG_IP_BAN_ALLOWLIST=

# Alerts (the instance name defaults to the hostname)
STACKDOG_NOTIFICATION_MIN_SEVERITY=high
#STACKDOG_SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
EOF`;

const serviceCommand = `sudo tee /etc/systemd/system/stackdog.service > /dev/null <<'EOF'
[Unit]
Description=Stackdog Security
After=network-online.target docker.service
Wants=network-online.target

[Service]
EnvironmentFile=/etc/stackdog/stackdog.env
WorkingDirectory=/var/lib/stackdog
ExecStart=/usr/local/bin/stackdog serve
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now stackdog`;

const testCommand = `# A harmless file that carries a known shell marker. It exits before doing anything.
sudo mkdir -p /var/www/html/wp-content/uploads
echo '<?php exit; /* stackdog detection test: c99shell */' \\
  | sudo tee /var/www/html/wp-content/uploads/stackdog-test.php > /dev/null

# One sniff pass is 30 seconds
sleep 40
curl -s http://127.0.0.1:5000/api/alerts | grep -o 'PHP shell indicators in [^"(]*'

# Clean up
sudo rm /var/www/html/wp-content/uploads/stackdog-test.php`;

const dailyCommands = `sudo stackdog firewall list          # who is banned right now
sudo stackdog unban 203.0.113.9      # release a ban
sudo stackdog ban-ip 203.0.113.9 --duration 24h --reason "webshell use"
curl -s http://127.0.0.1:5000/api/alerts   # alerts as JSON
sudo journalctl -u stackdog -f       # service log`;

const settingRows = [
  ['APP_HOST=127.0.0.1', 'The API has no login of its own. Keep it off the public interface; reach it over SSH or a VPN.'],
  ['STACKDOG_PHPSHELL_PATHS=/var/www', 'The host web roots to scan. Add every docroot you serve, comma-separated. PHP containers are found on their own.'],
  ['STACKDOG_LOG_SOURCES', 'Bans come from access-log lines, and host web server logs are not discovered automatically. List yours.'],
  ['STACKDOG_IP_BAN_MAX_RETRIES=5 / FIND_TIME_SECS=300', 'An attacker who keeps using a shell is banned within a few minutes; one stray request never bans anyone.'],
  ['STACKDOG_IP_BAN_BAN_TIME_SECS=1800', 'Bans lift by themselves after 30 minutes, so a mistake costs half an hour, not a lost customer.'],
  ['STACKDOG_IP_BAN_FROM_AI_FINDINGS=false', 'Start with bans from deterministic detectors only. Turn analyzer bans on once you have watched the alerts for a while.'],
  ['STACKDOG_IP_BAN_ALLOWLIST', 'Put anything here whose ban would take you down: office and VPN addresses, uptime monitors, load balancers.'],
  ['STACKDOG_NOTIFICATION_MIN_SEVERITY=high', 'Shell findings are High or Critical. Lower-severity posture findings stay in the dashboard instead of your inbox.']
] as const;

const faqEntries = [
  {
    question: 'My site is behind Cloudflare or another proxy. Is that a problem?',
    answer:
      'It is, until the access log records the real client. If nginx logs the proxy address, Stackdog would ban the proxy and with it every visitor. Configure real_ip (nginx) or mod_remoteip (Apache) first, or put the proxy ranges in STACKDOG_IP_BAN_ALLOWLIST.'
  },
  {
    question: 'My PHP sites run in Docker. Does this still work?',
    answer:
      'Yes. Running on the host, Stackdog finds PHP containers through the Docker socket and scans the docroots mounted into them. Container logs are discovered without any setting. If you run Stackdog itself in Docker, see the Compose setup on the detection page.'
  },
  {
    question: 'Will it delete the shell?',
    answer:
      'No. It alerts on the file and bans the addresses using it. Removing the file and finding how it got there stays with you; the detection page has a runbook.'
  },
  {
    question: 'Which release do I need?',
    answer:
      'v0.2.7 or later for PHP shell detection, v0.2.8 or later for the PHP2Shell version check, v0.2.9 or later for PHP2Shell attempt bans. The installer picks the latest release by default.'
  }
];

export const metadata: Metadata = {
  title: 'PHP Webshell Protection Quick Start',
  description:
    'Install Stackdog with one curl command and protect a PHP server from webshells: recommended settings, a systemd service, and a safe test.',
  keywords: [
    'PHP webshell protection',
    'install webshell scanner',
    'WordPress webshell scanner',
    'ban webshell attackers',
    'Stackdog Security'
  ],
  alternates: {
    canonical: PAGE_PATH
  },
  openGraph: {
    title: 'Protect a PHP server from webshells in five minutes',
    description: 'One curl command, one settings file, one service. Stackdog finds PHP shells and bans the clients using them.',
    url: getSiteUrl() + PAGE_PATH
  },
  twitter: {
    title: 'Protect a PHP server from webshells in five minutes',
    description: 'One curl command, one settings file, one service. Stackdog finds PHP shells and bans the clients using them.'
  }
};

function CodeSample({ code, label }: { code: string; label: string }) {
  return (
    <div className="panel p-4 sm:p-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="text-sm font-medium text-slate-200">{label}</p>
        <CopyButton text={code} label={`Copy ${label}`} />
      </div>
      <pre className="mt-4">
        <code>{code}</code>
      </pre>
    </div>
  );
}

function Step({
  number,
  title,
  children,
  code,
  label
}: {
  number: number;
  title: string;
  children: React.ReactNode;
  code: string;
  label: string;
}) {
  return (
    <li className="grid grid-cols-1 gap-6 lg:grid-cols-[minmax(0,2fr)_minmax(0,3fr)]">
      <div>
        <span className="text-sm font-semibold text-cyan-300">Step {number}</span>
        <h3 className="mt-3 text-2xl font-semibold text-white">{title}</h3>
        <div className="mt-3 space-y-3 text-sm leading-7 text-slate-400">{children}</div>
      </div>
      <div className="min-w-0">
        <CodeSample code={code} label={label} />
      </div>
    </li>
  );
}

export default function PhpShellQuickstartPage() {
  return (
    <main>
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{
          __html: toJsonLd(
            buildDocsStructuredData({
              title: 'Protect a PHP server from webshells in five minutes',
              description:
                'Install Stackdog with one curl command, apply recommended settings, run it as a service, and test PHP webshell detection safely.',
              url: getSiteUrl() + PAGE_PATH,
              about: ['PHP webshells', 'Linux server security', 'Automated IP banning'],
              sections: ['Install', 'Recommended settings', 'Service', 'Test', 'Everyday commands']
            })
          )
        }}
      />

      <section className="section-shell pt-12 sm:pt-16">
        <div className="site-container">
          <div className="max-w-3xl">
            <span className="eyebrow">PHP shell quick start</span>
            <h1 className="mt-6 text-balance text-4xl font-semibold tracking-tight text-white sm:text-5xl">
              Protect a PHP server from webshells in five minutes
            </h1>
            <p className="mt-6 text-lg leading-8 text-slate-400">
              One curl command installs Stackdog. One settings file points it at your web roots and
              access logs. From then on it scores every new or changed PHP file, alerts on shells, and
              bans the addresses that use them.
            </p>
          </div>
          <div className="mt-8 max-w-3xl">
            <CodeSample code={installCommand} label="Install" />
          </div>
          <p className="mt-4 text-sm text-slate-500">
            Linux x86_64 or aarch64, run as root. The binary goes to /usr/local/bin, and its SHA-256 is
            checked when the release publishes one.
          </p>
        </div>
      </section>

      <section id="steps" className="section-shell scroll-mt-24 border-y border-slate-800/70 bg-slate-900/30">
        <div className="site-container">
          <span className="eyebrow">Setup</span>
          <h2 className="section-heading mt-6">Four steps, all copy and paste</h2>
          <ol className="mt-10 space-y-14">
            <Step number={1} title="Install" code={installCommand} label="Install">
              <p>
                Downloads the latest release for your architecture and verifies its checksum. Add{' '}
                <code>-s -- --version vX.Y.Z</code> to pin a version.
              </p>
            </Step>
            <Step number={2} title="Write the recommended settings" code={envCommand} label="/etc/stackdog/stackdog.env">
              <p>
                These defaults ban only on clear evidence and lift every ban after 30 minutes. Before
                you go on, put your own addresses in <code>STACKDOG_IP_BAN_ALLOWLIST</code> and add any
                web root outside <code>/var/www</code>.
              </p>
              <p>
                The file is readable by root only, which matters once you add a Slack webhook or SMTP
                password.
              </p>
            </Step>
            <Step number={3} title="Run it as a service" code={serviceCommand} label="systemd unit">
              <p>
                <code>stackdog serve</code> runs a sniff pass every 30 seconds and serves the API on
                127.0.0.1:5000. It runs as root because it reads web roots and logs and writes firewall
                rules (nftables or iptables must be installed).
              </p>
            </Step>
            <Step number={4} title="Check that it sees a shell" code={testCommand} label="Safe test">
              <p>
                The test file carries a known shell marker but exits on its first line, so it is inert
                even if someone requests it. Expect one line naming the file.
              </p>
              <p>
                If nothing comes back, check that the path is under <code>STACKDOG_PHPSHELL_PATHS</code>{' '}
                and look for errors in <code>sudo journalctl -u stackdog -n 50</code>.
              </p>
            </Step>
          </ol>
        </div>
      </section>

      <section id="settings" className="section-shell scroll-mt-24">
        <div className="site-container">
          <span className="eyebrow">Why these defaults</span>
          <h2 className="section-heading mt-6">Strict on shells, careful with bans</h2>
          <p className="section-copy">
            A missed ban costs a few minutes; a wrong one locks out a customer. The settings above lean
            that way.
          </p>
          <div className="mt-10 grid grid-cols-1 gap-4 md:grid-cols-2">
            {settingRows.map(([name, reason]) => (
              <article key={name} className="panel p-5">
                <h3 className="break-words font-mono text-sm font-semibold text-cyan-200">{name}</h3>
                <p className="mt-2 text-sm leading-7 text-slate-400">{reason}</p>
              </article>
            ))}
          </div>
          <div className="panel mt-10 flex gap-4 border-amber-500/30 p-6">
            <ShieldAlert className="mt-1 h-5 w-5 flex-none text-amber-300" />
            <p className="text-sm leading-7 text-slate-300">
              Behind Cloudflare, a load balancer or any reverse proxy? Make your web server log the real
              client address first (nginx <code>real_ip</code>, Apache <code>mod_remoteip</code>).
              Otherwise the address in the log is the proxy, and a ban on it blocks every visitor.
            </p>
          </div>
        </div>
      </section>

      <section id="everyday" className="section-shell scroll-mt-24 border-y border-slate-800/70 bg-slate-900/30">
        <div className="site-container">
          <span className="eyebrow">Everyday commands</span>
          <h2 className="section-heading mt-6">Bans, releases, and what it found</h2>
          <div className="mt-10 max-w-3xl">
            <CodeSample code={dailyCommands} label="Commands" />
          </div>
        </div>
      </section>

      <section id="faq" className="section-shell scroll-mt-24">
        <div className="site-container">
          <span className="eyebrow">FAQ</span>
          <h2 className="section-heading mt-6">Before you install</h2>
          <div className="mt-10 grid grid-cols-1 gap-6 lg:grid-cols-2">
            {faqEntries.map((entry) => (
              <article key={entry.question} className="panel p-6">
                <h3 className="text-lg font-semibold text-white">{entry.question}</h3>
                <p className="mt-3 text-sm leading-7 text-slate-400">{entry.answer}</p>
              </article>
            ))}
          </div>
          <div className="mt-10 flex flex-wrap gap-4">
            <Link
              href="/php-shell-detection"
              className="inline-flex items-center gap-2 rounded-full bg-cyan-500 px-6 py-3 text-sm font-semibold text-slate-950 transition hover:bg-cyan-400"
            >
              How detection works
              <ArrowRight className="h-4 w-4" />
            </Link>
            <Link
              href="/docs"
              className="inline-flex items-center gap-2 rounded-full border border-slate-700 px-6 py-3 text-sm font-semibold text-slate-200 transition hover:border-cyan-400/50 hover:text-white"
            >
              Full documentation
            </Link>
          </div>
        </div>
      </section>
    </main>
  );
}
