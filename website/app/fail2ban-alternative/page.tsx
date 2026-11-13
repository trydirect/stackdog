import type { Metadata } from 'next';
import Link from 'next/link';
import { ArrowRight, Container, FileSearch, ShieldCheck, Timer } from 'lucide-react';
import { getSiteUrl } from '@/lib/config';
import { buildDocsStructuredData, toJsonLd } from '@/lib/structured-data';

const PAGE_PATH = '/fail2ban-alternative';

export const metadata: Metadata = {
  title: 'Fail2ban Alternative for Containers and Web Attacks',
  description:
    'Looking for a fail2ban alternative? StackdogApp keeps fail2ban-style IP bans for SSH floods and adds shipped detections for web attacks, webshells and PHP2Shell — with Docker container logs discovered automatically.',
  keywords: [
    'fail2ban alternative',
    'fail2ban vs',
    'fail2ban docker',
    'fail2ban containers',
    'fail2ban web application',
    'StackdogApp'
  ],
  alternates: {
    canonical: PAGE_PATH
  },
  openGraph: {
    title: 'Fail2ban Alternative for Containers and Web Attacks — StackdogApp',
    description:
      'fail2ban-style bans, shipped detections instead of per-error regex, and Docker container logs read like host logs.',
    url: getSiteUrl() + PAGE_PATH
  },
  twitter: {
    title: 'Fail2ban Alternative for Containers and Web Attacks — StackdogApp',
    description:
      'fail2ban-style bans, shipped detections instead of per-error regex, and Docker container logs read like host logs.'
  }
};

const comparisonRows = [
  [
    'Trigger',
    'Too many failed logins in a log line — its README describes scanning logs like /var/log/auth.log',
    'The same SSH/PAM failures, plus shipped detections: SQL injection probes, path traversal, brute force, webshell access, PHP2Shell attempts'
  ],
  [
    'Configuration',
    'Per error: it reads "any log file of your choosing, for any error you wish" — each one is a jail and a filter you maintain',
    'The detections ship with the product. Thresholds are env vars (five offenses in five minutes by default)'
  ],
  [
    'Log sources',
    'Host log files; out of the box sshd and Apache',
    'Host logs and Docker container logs, discovered on their own; nginx, Apache and application formats'
  ],
  [
    'What it correlates',
    'One log line at a time',
    'Files and requests: a webshell is a file on disk and a request to it — StackdogApp reads both and bans whoever drives the shell'
  ],
  [
    'Ban mechanics',
    'Updates system firewall rules for a configurable time',
    'iptables/nftables rules with their own marker, reconciled against the database: a crash strands neither a ban nor a phantom rule. Bans expire and release themselves'
  ],
  [
    'Safety rails',
    'Configured per jail',
    'Allowlist, private and local infrastructure never banned, Docker network subnets protected automatically, per-minute cap on new bans'
  ]
];

const differences = [
  {
    icon: Container,
    title: 'Containers are first-class',
    body: 'Your PHP lives in containers, so its logs do too. StackdogApp discovers container logs and reads them like host files — no bind-mounting logs out of containers to satisfy a host-side daemon.'
  },
  {
    icon: FileSearch,
    title: 'Detections, not regex maintenance',
    body: 'Every new attack pattern in a fail2ban setup waits for someone to write a filter. StackdogApp ships the patterns — including the PHP2Shell crash step, where the footprint is "in Unknown on line 0", not a payload.'
  },
  {
    icon: Timer,
    title: 'Unban is part of the design',
    body: 'Bans expire and release themselves; the firewall and the database are reconciled every pass, so a restart cannot strand a block or leave a stale drop rule behind.'
  },
  {
    icon: ShieldCheck,
    title: 'One product, not a pile of jails',
    body: 'SSH floods, web attacks, webshells and PHP version exposure are one pipeline: one alert stream, one ban engine, one place to look when something happened.'
  }
];

export default function Fail2BanAlternativePage() {
  return (
    <main>
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{
          __html: toJsonLd(
            buildDocsStructuredData({
              title: 'Fail2ban Alternative for Containers and Web Attacks',
              description:
                'How StackdogApp compares to fail2ban: the same SSH flood bans, shipped web-attack detections, and Docker container logs read like host logs.',
              url: getSiteUrl() + PAGE_PATH,
              about: ['fail2ban alternative', 'IP banning', 'Docker security', 'Web application security'],
              sections: ['What changes', 'Side by side', 'In production', 'Honest limits']
            })
          )
        }}
      />

      <section className="section-shell pt-12 sm:pt-16">
        <div className="site-container">
          <div className="max-w-3xl">
            <span className="eyebrow">fail2ban alternative</span>
            <h1 className="mt-6 text-balance text-4xl font-semibold tracking-tight text-white sm:text-5xl">
              You outgrew fail2ban. Here is the honest replacement.
            </h1>
            <p className="mt-6 text-lg leading-8 text-slate-400">
              fail2ban does one pattern well — its own README says so: scan logs, ban IPs with too
              many failed logins, update firewall rules for a configurable time. StackdogApp keeps
              that pattern: SSH floods and PAM failures are banned the same way, five offenses in
              five minutes by default. What changes is everything around it.
            </p>
            <div className="mt-8 flex flex-wrap items-center gap-4">
              <Link
                href="/php-shell-quickstart"
                className="inline-flex items-center gap-2 rounded-full bg-cyan-500 px-6 py-3 text-sm font-semibold text-slate-950 transition hover:bg-cyan-400"
              >
                Install StackdogApp
                <ArrowRight className="h-4 w-4" />
              </Link>
              <Link
                href="/php2shell-check"
                className="inline-flex items-center gap-2 rounded-full border border-slate-700 px-6 py-3 text-sm font-semibold text-slate-200 transition hover:border-cyan-400/50 hover:text-white"
              >
                Free PHP2Shell version check
              </Link>
            </div>
          </div>
        </div>
      </section>

      <section id="what-changes" className="section-shell scroll-mt-24 border-y border-slate-800/70 bg-slate-900/30">
        <div className="site-container">
          <span className="eyebrow">What changes</span>
          <h2 className="section-heading mt-6">The same bans, minus the filter maintenance</h2>
          <div className="mt-10 grid gap-6 lg:grid-cols-2">
            {differences.map((item) => {
              const Icon = item.icon;
              return (
                <article key={item.title} className="panel p-6">
                  <div className="inline-flex h-12 w-12 items-center justify-center rounded-2xl border border-cyan-500/20 bg-cyan-500/10 text-cyan-300">
                    <Icon className="h-5 w-5" />
                  </div>
                  <h3 className="mt-4 text-lg font-semibold text-white">{item.title}</h3>
                  <p className="mt-3 text-sm leading-7 text-slate-400">{item.body}</p>
                </article>
              );
            })}
          </div>
        </div>
      </section>

      <section id="side-by-side" className="section-shell scroll-mt-24">
        <div className="site-container">
          <span className="eyebrow">Side by side</span>
          <h2 className="section-heading mt-6">fail2ban and StackdogApp, compared on what they actually do</h2>
          <div className="mt-10">
            <DataTable headers={['', 'fail2ban', 'StackdogApp']} rows={comparisonRows} />
          </div>
          <p className="mt-6 text-sm leading-7 text-slate-400">
            The fail2ban column quotes its own README. Both tools agree on the thing fail2ban
            writes there itself: firewall rules reduce the rate of attacks, they do not replace
            good authentication.
          </p>
        </div>
      </section>

      <section
        id="in-production"
        className="section-shell scroll-mt-24 border-y border-slate-800/70 bg-slate-900/30"
      >
        <div className="site-container">
          <span className="eyebrow">In production</span>
          <h2 className="section-heading mt-6">Verified end-to-end against real scanners</h2>
          <p className="section-copy">
            Not a lab benchmark. The ban pipeline runs against real traffic on our own shop:
            offenses from the detectors, bans with expiry times, tagged DROP rules in the
            firewall — and every pass reconciles the two so they cannot drift apart. This is what
            that looked like on the morning of 1 November 2026:
          </p>
          <div className="mt-8 max-w-3xl">
            <div className="panel p-4 sm:p-5">
              <pre className="overflow-x-auto">
                <code>{`$ stackdog firewall list
Firewall rules (tagged stackdog):
  -s 103.86.198.162 -j DROP
  -s 41.242.115.83 -j DROP
  -s 64.89.163.175 -j DROP
  …
Database blocks:
  103.86.198.162 until 2026-11-02T16:52:06Z (sniff)
  41.242.115.83 until 2026-11-02T16:52:05Z (sniff)
  64.89.163.175 until 2026-11-02T16:52:05Z (sniff)
  …`}</code>
              </pre>
            </div>
          </div>
          <p className="mt-6 max-w-3xl text-sm leading-7 text-slate-400">
            Eight addresses on the list, eight database blocks — the same eight. That agreement is
            the reconciliation you can see in the output, and it is the same code path that runs
            on your box. One deployment is one deployment, though: run it alongside fail2ban for a
            week before you switch.
          </p>
        </div>
      </section>

      <section id="limits" className="section-shell scroll-mt-24">
        <div className="site-container">
          <span className="eyebrow">Honest limits</span>
          <h2 className="section-heading mt-6">Where fail2ban is still the better fit</h2>
          <div className="mt-6 max-w-3xl space-y-4 text-sm leading-7 text-slate-400">
            <p>
              IPv6. fail2ban has matched IPv6 addresses since v0.10; StackdogApp bans IPv4 dotted
              quads only. If your traffic is v6-heavy, that difference matters.
            </p>
            <p>
              Maturity. fail2ban is packaged for most distributions and has run on plain hosts for
              years. StackdogApp&apos;s ban pipeline (tagged iptables/nftables rules, reconciled
              against its own database every pass) is verified end-to-end in production against
              real scanners — but it is newer. Run both for a week before you switch.
            </p>
            <p>
              Plain SSH on one host. fail2ban does that job and needs nothing else. An
              &quot;alternative&quot; is for the box that grew containers, web apps and attack
              patterns no jail reads.
            </p>
          </div>
          <div className="mt-10">
            <Link
              href="/php-shell-detection"
              className="inline-flex items-center gap-2 rounded-full bg-cyan-500 px-6 py-3 text-sm font-semibold text-slate-950 transition hover:bg-cyan-400"
            >
              See what it detects
              <ArrowRight className="h-4 w-4" />
            </Link>
          </div>
        </div>
      </section>
    </main>
  );
}

function DataTable({
  headers,
  rows
}: {
  headers: readonly string[];
  rows: readonly (readonly string[])[];
}) {
  return (
    <div className="overflow-hidden rounded-2xl border border-slate-800">
      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-slate-800 text-left text-sm">
          <thead className="bg-slate-900/80 text-slate-200">
            <tr>
              {headers.map((header) => (
                <th key={header} scope="col" className="px-4 py-3 font-medium">
                  {header}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800 bg-slate-950/60 text-slate-300">
            {rows.map((row) => (
              <tr key={row.join('-')}>
                {row.map((cell, index) => (
                  <td
                    key={cell}
                    className={`px-4 py-3 align-top leading-7 ${index === 0 ? 'whitespace-nowrap font-medium text-slate-200' : 'min-w-[14rem]'}`}
                  >
                    {cell}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
