import type { Metadata } from 'next';
import Link from 'next/link';
import { ArrowRight, PackageSearch, ShieldAlert, TerminalSquare } from 'lucide-react';
import CopyButton from '@/components/CopyButton';
import { getSiteUrl } from '@/lib/config';
import { buildDocsStructuredData, toJsonLd } from '@/lib/structured-data';

const PAGE_PATH = '/monitoring-stack-security-events';

export const metadata: Metadata = {
  title: 'Three Security Events in One Month Reshaped Our Monitoring Stack',
  description:
    'PHP2Shell, SSHole and a month of automated exploitation taught Stackdog new layers: version checks, first-line bans, and a CVE watch that matches every installed package against OSV and CISA KEV. Now on brew and cargo.',
  keywords: [
    'Stackdog',
    'PHP2Shell',
    'SSHole',
    'CVE watch',
    'monitoring stack',
    'self-hosted security'
  ],
  alternates: {
    canonical: PAGE_PATH
  },
  openGraph: {
    title: 'Three Security Events in One Month Reshaped Our Monitoring Stack — StackdogApp',
    description:
      'Where Stackdog stands after PHP2Shell and SSHole, and why it now installs with one command.',
    url: getSiteUrl() + PAGE_PATH
  },
  twitter: {
    title: 'Three Security Events in One Month Reshaped Our Monitoring Stack — StackdogApp',
    description:
      'Where Stackdog stands after PHP2Shell and SSHole, and why it now installs with one command.'
  }
};

const layers = [
  {
    icon: ShieldAlert,
    title: 'PHP2Shell (v0.2.8–0.2.9)',
    body: 'Forced the version-check layer: which PHP builds predate the fix, on the host and inside every running container — and a detector for the exploit\u2019s actual footprint, the request that runs PHP out of memory while it is still being parsed.'
  },
  {
    icon: TerminalSquare,
    title: 'SSHole (v0.3.0)',
    body: 'Repeated the pattern for OpenSSH in days, and added the policy that one password login to a key-only account is already a foothold: first line bans.'
  },
  {
    icon: PackageSearch,
    title: 'v0.3.1: CVE watch',
    body: 'Generalized it: CVE watch now matches every installed package against OSV and CISA\u2019s exploited-vulnerability catalog, so next month\u2019s incident needs no release from us.'
  }
];

const installCommands = [
  {
    label: 'Homebrew',
    code: 'brew install trydirect/tap/stackdog'
  },
  {
    label: 'cargo',
    code: 'cargo install stackdog'
  }
];

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

export default function MonitoringStackSecurityEventsPage() {
  return (
    <main>
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{
          __html: toJsonLd(
            buildDocsStructuredData({
              title: 'Three Security Events in One Month Reshaped Our Monitoring Stack',
              description:
                'PHP2Shell, SSHole and CVE watch: how three security events taught Stackdog new layers, and why it now installs with one command.',
              url: getSiteUrl() + PAGE_PATH,
              about: ['Stackdog', 'PHP2Shell', 'SSHole', 'CVE watch'],
              sections: [
                'Three events, three layers',
                'Underneath',
                'Install today',
                'Honest limits'
              ]
            })
          )
        }}
      />

      <section className="section-shell pt-12 sm:pt-16">
        <div className="site-container">
          <div className="max-w-3xl">
            <span className="eyebrow">From the changelog</span>
            <h1 className="mt-6 text-balance text-4xl font-semibold tracking-tight text-white sm:text-5xl">
              Three security events in one month reshaped our monitoring stack
            </h1>
            <p className="mt-6 text-lg leading-8 text-slate-400">
              Stackdog is not a weekend project. It is what we run on our own servers and with our
              own customers, and it has been through enough releases that the changelog is now the
              best account of its education.
            </p>
            <p className="mt-4 text-lg leading-8 text-slate-400">
              The short version of that education: October and November were brutal. PHP got two
              remote-code-execution bugs (PHP2Shell, late October), OpenSSH got an authentication
              bypass (SSHole, early November), and both were under automated exploitation within
              hours of disclosure. Each one taught the stack a new layer.
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
                Free PHP2Shell check
              </Link>
            </div>
          </div>
        </div>
      </section>

      <section
        id="three-layers"
        className="section-shell scroll-mt-24 border-y border-slate-800/70 bg-slate-900/30"
      >
        <div className="site-container">
          <span className="eyebrow">Three events, three layers</span>
          <h2 className="section-heading mt-6">What each incident taught the stack</h2>
          <div className="mt-10 grid gap-6 lg:grid-cols-3">
            {layers.map((layer) => {
              const Icon = layer.icon;
              return (
                <article key={layer.title} className="panel p-6">
                  <div className="inline-flex h-12 w-12 items-center justify-center rounded-2xl border border-cyan-500/20 bg-cyan-500/10 text-cyan-300">
                    <Icon className="h-5 w-5" />
                  </div>
                  <h3 className="mt-4 text-lg font-semibold text-white">{layer.title}</h3>
                  <p className="mt-3 text-sm leading-7 text-slate-400">{layer.body}</p>
                </article>
              );
            })}
          </div>
          <p className="mt-8 max-w-3xl text-sm leading-7 text-slate-400">
            Deeper on each layer:{' '}
            <Link href="/php2shell-check" className="text-cyan-300 hover:text-cyan-200">
              the PHP2Shell check
            </Link>
            ,{' '}
            <Link href="/sshole-check" className="text-cyan-300 hover:text-cyan-200">
              the SSHole check
            </Link>{' '}
            and{' '}
            <Link href="/php-shell-detection" className="text-cyan-300 hover:text-cyan-200">
              the detection stack
            </Link>
            .
          </p>
        </div>
      </section>

      <section id="underneath" className="section-shell scroll-mt-24">
        <div className="site-container">
          <span className="eyebrow">Underneath</span>
          <h2 className="section-heading mt-6">What predates all of it</h2>
          <p className="section-copy">
            Webshell scanning that correlates a file on disk with the request that drives it. An IP
            ban engine whose firewall rules are reconciled against its own database every pass.
            fail2ban-style SSH protection. Worker-crash watching. The comparison with fail2ban has
            its own{' '}
            <Link href="/fail2ban-alternative" className="text-cyan-300 hover:text-cyan-200">
              page
            </Link>
            .
          </p>
        </div>
      </section>

      <section
        id="install"
        className="section-shell scroll-mt-24 border-y border-slate-800/70 bg-slate-900/30"
      >
        <div className="site-container">
          <span className="eyebrow">Install today</span>
          <h2 className="section-heading mt-6">One command, then an optional one</h2>
          <div className="mt-10 grid grid-cols-1 gap-6 lg:grid-cols-2">
            {installCommands.map((command) => (
              <CodeSample key={command.label} code={command.code} label={command.label} />
            ))}
          </div>
          <p className="mt-6 max-w-3xl text-sm leading-7 text-slate-400">
            <code>stackdog init</code> writes a starter config. Every setting has a safe default, so
            it runs with nothing configured at all. Alerts go to Slack, Discord, Telegram, email or
            a webhook.
          </p>
          <figure className="mt-10 max-w-3xl">
            <img
              src="/stackdog-demo.gif"
              alt="Split-screen demo: the server protected by Stackdog on the left, the attacker on the right, ending with a firewall DROP rule"
              width={1280}
              height={720}
              className="w-full rounded-2xl border border-slate-800"
            />
            <figcaption className="mt-3 text-xs leading-6 text-slate-500">
              The whole chain on a lab server, every line real output: the shell is dropped, the
              requests come from an address our production ban lists already know, and after five
              of them the address is in the firewall. The lab runs in Docker on a documentation
              subnet; no real host was harmed.
            </figcaption>
          </figure>
          <figure className="mt-10 max-w-3xl">
            <img
              src="/stackdog-terminal.png"
              alt="stackdog terminal: install, version, and firewall list with banned scanner addresses"
              width={1280}
              height={860}
              className="w-full rounded-2xl border border-slate-800"
            />
            <figcaption className="mt-3 text-xs leading-6 text-slate-500">
              The firewall list is from our own VPS, where the ban engine has been handling real
              scanner traffic since October.
            </figcaption>
          </figure>
        </div>
      </section>

      <section id="limits" className="section-shell scroll-mt-24">
        <div className="site-container">
          <span className="eyebrow">Honest limits</span>
          <h2 className="section-heading mt-6">What it does not do</h2>
          <div className="mt-6 max-w-3xl space-y-4 text-sm leading-7 text-slate-400">
            <p>
              It doesn&apos;t patch anything (upgrading is the fix), a ban arrives after the fact
              and mostly stops scanners and repeat attempts, bans are IPv4-only right now, and
              version-based CVE findings mean &quot;a fix is missing&quot;, not &quot;you are
              exploitable&quot; — distributions backport fixes. Every alert says to check your
              vendor&apos;s advisory.
            </p>
            <p>
              Happy to answer questions about the detection side — and if you&apos;ve been hit by
              something the logs didn&apos;t catch, we genuinely want to hear about it.{' '}
              <Link href="/contact" className="text-cyan-300 hover:text-cyan-200">
                Contact us
              </Link>
              .
            </p>
          </div>
        </div>
      </section>
    </main>
  );
}
