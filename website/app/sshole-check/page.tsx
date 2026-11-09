import type { Metadata } from 'next';
import Link from 'next/link';
import { ArrowRight, ShieldCheck, TerminalSquare } from 'lucide-react';
import SsholeChecker from '@/components/SsholeChecker';
import { getSiteUrl } from '@/lib/config';
import { buildDocsStructuredData, toJsonLd } from '@/lib/structured-data';

const PAGE_PATH = '/sshole-check';

export const metadata: Metadata = {
  title: 'Am I Affected by SSHole? Check Your OpenSSH Version',
  description:
    'Free SSHole check for CVE-2026-123158: paste ssh -V, see whether your OpenSSH predates the 10.6p2 fix, and learn how StackdogApp detects the version exposure and the logins a successful attack leaves behind.',
  keywords: [
    'SSHole check',
    'CVE-2026-123158',
    'OpenSSH vulnerability check',
    'OpenSSH 10.6p2',
    'Alpine Linux sshd',
    'StackdogApp'
  ],
  alternates: {
    canonical: PAGE_PATH
  },
  openGraph: {
    title: 'Am I Affected by SSHole? — StackdogApp',
    description:
      'Paste ssh -V and see whether your OpenSSH predates the SSHole fix. Plus how StackdogApp checks it on every sniff pass.',
    url: getSiteUrl() + PAGE_PATH
  },
  twitter: {
    title: 'Am I Affected by SSHole? — StackdogApp',
    description:
      'Paste ssh -V and see whether your OpenSSH predates the SSHole fix. Plus how StackdogApp checks it.'
  }
};

const checks = [
  [
    'vuln.sshole',
    'An OpenSSH build older than 10.6p2 on a musl system: the package database on the host and inside every running container (openssh-server on Alpine)',
    'Critical alert. Names the version and says to upgrade to 10.6p2 and restart sshd. Never bans: a version names no attacker.'
  ],
  [
    'ssh.password-login',
    'A password login to a key-only account (root, alpine by default; more via STACKDOG_SSHOLE_KEYONLY_USERS). That is what a successful SSHole login looks like in the logs',
    'Alert and an offense per line. Five from one address within the ban window and the address is banned. Allowlists still apply.'
  ]
] as const;

export default function SsholeCheckPage() {
  return (
    <main>
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{
          __html: toJsonLd(
            buildDocsStructuredData({
              title: 'Am I Affected by SSHole? Check Your OpenSSH Version',
              description:
                'A free SSHole (CVE-2026-123158) check against the OpenSSH 10.6p2 fix, plus how StackdogApp detects the exposure and the logins a successful attack leaves behind.',
              url: getSiteUrl() + PAGE_PATH,
              about: ['SSHole', 'CVE-2026-123158', 'OpenSSH security', 'Version check'],
              sections: [
                'The check',
                'What SSHole is',
                'What to do now',
                'How StackdogApp checks it',
                'Honest limits'
              ]
            })
          )
        }}
      />

      <section className="section-shell pt-12 sm:pt-16">
        <div className="site-container">
          <div className="max-w-3xl">
            <span className="eyebrow">Free SSHole check</span>
            <h1 className="mt-6 text-balance text-4xl font-semibold tracking-tight text-white sm:text-5xl">
              Am I affected by SSHole?
            </h1>
            <p className="mt-6 text-lg leading-8 text-slate-400">
              SSHole (CVE-2026-123158) is an authentication bypass in OpenSSH itself: on musl
              systems with PAM disabled, including Alpine&apos;s default server configuration, an
              oversized password logs the attacker into accounts that have no password set. It
              was being exploited within hours of disclosure. The fix is OpenSSH 10.6p2. Paste
              your version below.
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
                PHP2Shell check
              </Link>
            </div>
          </div>
        </div>
      </section>

      <section
        id="the-check"
        className="section-shell scroll-mt-24 border-y border-slate-800/70 bg-slate-900/30"
      >
        <div className="site-container">
          <span className="eyebrow">The check</span>
          <h2 className="section-heading mt-6">One paste, no sign-up, nothing leaves your browser</h2>
          <div className="mt-10 max-w-3xl">
            <SsholeChecker />
          </div>
        </div>
      </section>

      <section id="what-it-is" className="section-shell scroll-mt-24">
        <div className="site-container">
          <span className="eyebrow">What SSHole is</span>
          <h2 className="section-heading mt-6">A failed hash read as a successful login</h2>
          <div className="mt-6 max-w-3xl space-y-4 text-sm leading-7 text-slate-400">
            <p>
              Accounts with no usable password carry a <code>*</code> in their password field.
              When OpenSSH checks a password without PAM, a 257 to 1024 byte password makes the
              hashing step fail, and the failure is read as the same <code>*</code>. The stored
              asterisk and the produced asterisk match, and the login succeeds. No credentials
              stolen, no brute force, one request.
            </p>
            <p>
              The condition is narrow and precise: Linux, musl, OpenSSH with passwords checked
              without PAM, and at least one account whose password field is <code>*</code>.
              Dropbear is not affected, glibc distributions are not affected, and systems that
              check passwords through PAM are not affected. That covers the vulnerable class:
              Alpine&apos;s default OpenSSH server.
            </p>
          </div>
        </div>
      </section>

      <section
        id="what-to-do"
        className="section-shell scroll-mt-24 border-y border-slate-800/70 bg-slate-900/30"
      >
        <div className="site-container">
          <span className="eyebrow">What to do now</span>
          <h2 className="section-heading mt-6">Upgrade, restart, then look for what already got in</h2>
          <div className="mt-8 grid grid-cols-1 gap-6 lg:grid-cols-2">
            <div className="panel p-6">
              <div className="inline-flex h-12 w-12 items-center justify-center rounded-2xl border border-cyan-500/20 bg-cyan-500/10 text-cyan-300">
                <TerminalSquare className="h-5 w-5" />
              </div>
              <h3 className="mt-4 text-lg font-semibold text-white">Fix the version</h3>
              <p className="mt-3 text-sm leading-7 text-slate-400">
                Install OpenSSH 10.6p2, or your distribution&apos;s patched package — on Alpine
                that is <code>10.6_p2-r0</code> or newer — and then restart sshd. Until the
                restart, the old code is still serving logins.
              </p>
            </div>
            <div className="panel p-6">
              <div className="inline-flex h-12 w-12 items-center justify-center rounded-2xl border border-cyan-500/20 bg-cyan-500/10 text-cyan-300">
                <ShieldCheck className="h-5 w-5" />
              </div>
              <h3 className="mt-4 text-lg font-semibold text-white">Hunt what got in</h3>
              <p className="mt-3 text-sm leading-7 text-slate-400">
                Alpine&apos;s own incident advice: look for <code>Accepted password for</code>{' '}
                lines involving accounts that should never accept a password. Review doas use,
                recently created users, files and authorized keys. If you cannot rule out a
                login, treat the machine as compromised.
              </p>
            </div>
          </div>
        </div>
      </section>

      <section id="how-stackdog-checks" className="section-shell scroll-mt-24">
        <div className="site-container">
          <span className="eyebrow">How StackdogApp checks it</span>
          <h2 className="section-heading mt-6">The version, and the logs a successful attack leaves</h2>
          <p className="section-copy">
            The same two-layer shape as PHP2Shell: one detector for exposure, one for the
            evidence. Both run on every sniff pass.
          </p>
          <div className="mt-10">
            <DataTable headers={['Finding', 'When', 'Action']} rows={checks} />
          </div>
          <p className="mt-6 max-w-3xl text-sm leading-7 text-slate-400">
            The version check reads the apk package database, because musl is the affected half
            of the configuration and the package database says musl: the default{' '}
            <code>openssh-server</code> on Alpine is built without PAM. The PAM flavor and glibc
            distributions are not reported, because the CVE does not reach them. The log half
            reads the same auth and syslog sources the brute-force bans come from — list yours in{' '}
            <code>STACKDOG_LOG_SOURCES</code>; on Alpine, sshd logs to{' '}
            <code>/var/log/messages</code>.
          </p>
        </div>
      </section>

      <section
        id="limits"
        className="section-shell scroll-mt-24 border-y border-slate-800/70 bg-slate-900/30"
      >
        <div className="site-container">
          <span className="eyebrow">Honest limits</span>
          <h2 className="section-heading mt-6">What the checks do not cover</h2>
          <div className="mt-6 max-w-3xl space-y-4 text-sm leading-7 text-slate-400">
            <p>
              The log detector knows key-only accounts only because we name them: root and
              alpine by default, your own via{' '}
              <code>STACKDOG_SSHOLE_KEYONLY_USERS</code>. A password login to an unnamed
              key-only account passes it by.
            </p>
            <p>
              One successful SSHole login is already a foothold. The ban stops repeat sessions
              and scanners; it does not undo the first one. If the check or the logs say a
              password login reached a key-only account, the work is incident response, not
              tuning.
            </p>
            <p>
              The version check covers musl systems read from package databases. An OpenSSH
              built from source carries no package to read. And none of this patches anything:
              upgrading is the fix, same as always.
            </p>
          </div>
          <div className="mt-10">
            <Link
              href="/php-shell-detection"
              className="inline-flex items-center gap-2 rounded-full bg-cyan-500 px-6 py-3 text-sm font-semibold text-slate-950 transition hover:bg-cyan-400"
            >
              See the rest of the detection stack
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
