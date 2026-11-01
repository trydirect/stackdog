import type { Metadata } from 'next';
import Link from 'next/link';
import { ArrowRight, ShieldCheck } from 'lucide-react';
import PhpVersionChecker from '@/components/PhpVersionChecker';
import { getSiteUrl } from '@/lib/config';
import { buildDocsStructuredData, toJsonLd } from '@/lib/structured-data';

const PAGE_PATH = '/php2shell-check';

export const metadata: Metadata = {
  title: 'Am I Affected by PHP2Shell? Check Your PHP Version',
  description:
    'Free PHP2Shell version check for CVE-2026-109618 and CVE-2026-109619. Paste the output of php -v and see whether your build predates the fixed releases.',
  keywords: [
    'PHP2Shell check',
    'CVE-2026-109618',
    'CVE-2026-109619',
    'PHP vulnerability check',
    'PHP version checker',
    'PHP2Shell patched versions'
  ],
  alternates: {
    canonical: PAGE_PATH
  },
  openGraph: {
    title: 'Am I Affected by PHP2Shell? — StackdogApp',
    description:
      'Paste the output of php -v and see whether your build predates the PHP2Shell fixes.',
    url: getSiteUrl() + PAGE_PATH
  },
  twitter: {
    title: 'Am I Affected by PHP2Shell? — StackdogApp',
    description:
      'Paste the output of php -v and see whether your build predates the PHP2Shell fixes.'
  }
};

export default function Php2ShellCheckPage() {
  return (
    <main>
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{
          __html: toJsonLd(
            buildDocsStructuredData({
              title: 'Am I Affected by PHP2Shell? Check Your PHP Version',
              description:
                'A free version check for PHP2Shell (CVE-2026-109618, CVE-2026-109619) against the fixed releases 8.2.35, 8.3.36, 8.4.27 and 8.5.12.',
              url: getSiteUrl() + PAGE_PATH,
              about: ['PHP2Shell', 'CVE-2026-109618', 'PHP security', 'Version check'],
              sections: ['The check', 'Fixed releases', 'What the check does not cover']
            })
          )
        }}
      />

      <section className="section-shell pt-12 sm:pt-16">
        <div className="site-container">
          <div className="max-w-3xl">
            <span className="eyebrow">Free PHP2Shell check</span>
            <h1 className="mt-6 text-balance text-4xl font-semibold tracking-tight text-white sm:text-5xl">
              Am I affected by PHP2Shell?
            </h1>
            <p className="mt-6 text-lg leading-8 text-slate-400">
              PHP2Shell (CVE-2026-109618, CVE-2026-109619) is two bugs in the PHP interpreter
              itself, fixed on 22 October 2026 as four releases at once. Paste the output of{' '}
              <code>php -v</code> below and see whether your build predates them.
            </p>
            <div className="mt-8 flex flex-wrap items-center gap-4">
              <Link
                href="/php-shell-detection"
                className="inline-flex items-center gap-2 rounded-full bg-cyan-500 px-6 py-3 text-sm font-semibold text-slate-950 transition hover:bg-cyan-400"
              >
                How StackdogApp watches for it
                <ArrowRight className="h-4 w-4" />
              </Link>
              <Link
                href="/php-shell-quickstart"
                className="inline-flex items-center gap-2 rounded-full border border-slate-700 px-6 py-3 text-sm font-semibold text-slate-200 transition hover:border-cyan-400/50 hover:text-white"
              >
                Install StackdogApp
              </Link>
            </div>
          </div>
        </div>
      </section>

      <section id="the-check" className="section-shell scroll-mt-24 border-y border-slate-800/70 bg-slate-900/30">
        <div className="site-container">
          <span className="eyebrow">The check</span>
          <h2 className="section-heading mt-6">One paste, no sign-up, nothing leaves your browser</h2>
          <div className="mt-10 max-w-3xl">
            <PhpVersionChecker />
          </div>
        </div>
      </section>

      <section id="fixed-releases" className="section-shell scroll-mt-24">
        <div className="site-container">
          <span className="eyebrow">Fixed releases</span>
          <h2 className="section-heading mt-6">What the fix looks like in PHP&apos;s changelog</h2>
          <p className="section-copy">
            The same entry appears in all four releases, dated 22 October 2026: &quot;avoid state
            corruption via bailout&quot;. A bailout is the emergency exit PHP takes when a request
            hits a fatal error — memory exhaustion is the easy way to force one. Branches older
            than 8.2 got no fix.
          </p>
          <div className="mt-8 grid grid-cols-2 gap-4 sm:grid-cols-4">
            {['8.2.35', '8.3.36', '8.4.27', '8.5.12'].map((release) => (
              <div key={release} className="panel flex items-center gap-3 p-5">
                <ShieldCheck className="h-5 w-5 text-emerald-300" />
                <div>
                  <p className="text-lg font-semibold text-white">{release}</p>
                  <p className="text-xs text-slate-400">fixed</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section
        id="limits"
        className="section-shell scroll-mt-24 border-y border-slate-800/70 bg-slate-900/30"
      >
        <div className="site-container">
          <span className="eyebrow">Honest limits</span>
          <h2 className="section-heading mt-6">What the check does not cover</h2>
          <div className="mt-6 max-w-3xl space-y-4 text-sm leading-7 text-slate-400">
            <p>
              It reads only the version string. Debian, Ubuntu and Alpine packages backport fixes
              without changing that number, so a &quot;predates the fix&quot; result on a
              distribution package means: check your vendor&apos;s advisory, not that you are
              certainly vulnerable.
            </p>
            <p>
              It does not patch anything, and it cannot tell whether an attacker has already
              succeeded. Upgrading PHP is the fix; everything else buys time.
            </p>
            <p>
              The <Link href="/php-shell-detection" className="text-cyan-300 hover:text-cyan-200">StackdogApp version check</Link>{' '}
              runs the same comparison for you on every sniff pass — on the host and inside every
              running container, from package databases and the official images&apos;{' '}
              <code>PHP_VERSION</code> — and pairs it with a ban layer for clients whose requests
              trip the crash step.
            </p>
          </div>
        </div>
      </section>
    </main>
  );
}
