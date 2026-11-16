import type { Metadata } from 'next';
import Link from 'next/link';
import { ArrowRight, Boxes, FileSearch, ShieldAlert, TerminalSquare } from 'lucide-react';
import CopyButton from '@/components/CopyButton';
import { getSiteUrl } from '@/lib/config';
import { buildDocsStructuredData, toJsonLd } from '@/lib/structured-data';

const PAGE_PATH = '/ai-built-startup-security';

const installCommand =
  'curl -fsSL https://raw.githubusercontent.com/trydirect/stackdog/main/install.sh | sudo bash';

const envSnippet = `STACKDOG_PHPSHELL_ENABLED=true
STACKDOG_PHPSHELL_PATHS=/var/www
STACKDOG_PHP_VERSION_CHECK_ENABLED=true
STACKDOG_LOG_SOURCES=/var/log/nginx/access.log,/var/log/apache2/access.log,\\
/var/log/apache2/error.log,/var/log/nginx/error.log
STACKDOG_IP_BAN_ENABLED=true
STACKDOG_IP_BAN_MAX_RETRIES=5
STACKDOG_IP_BAN_FIND_TIME_SECS=300
STACKDOG_IP_BAN_BAN_TIME_SECS=1800
STACKDOG_IP_BAN_PROTECT_LOCAL_IPS=true
STACKDOG_IP_BAN_ALLOWLIST=`;

const verifyCommand = 'curl -s http://127.0.0.1:5000/api/alerts';

const checklist = [
  'StackdogApp installed and stackdog serve running.',
  'Every web root in STACKDOG_PHPSHELL_PATHS.',
  'Host access and error logs in STACKDOG_LOG_SOURCES.',
  'Allowlist filled before the first false positive, not after.',
  'PHP builds checked against the fixed releases; upgrade scheduled.',
  'If you cannot upgrade immediately: session.upload_progress.enabled = 0 is the interim mitigation the alert names.'
];

const earlyAttacks = [
  {
    icon: ShieldAlert,
    title: 'Scanners',
    body: 'Automated crawlers probing for known shells, admin panels and misconfigurations. On our own shop, eight scanner addresses ended up in the firewall DROP list in one morning, tagged rules and database records agreeing on all eight. Nobody attacked us specifically; that is just what a public IP receives.'
  },
  {
    icon: TerminalSquare,
    title: 'Brute force',
    body: 'Repeated SSH and login failures from rented infrastructure. The oldest attack on the internet, and it works on weekend servers because nobody configured a ban threshold.'
  },
  {
    icon: FileSearch,
    title: 'Exploit probes',
    body: 'Requests that try known flaws against whatever you happen to be running. PHP2Shell (CVE-2026-109618, CVE-2026-109619) is the current example: two bugs in the PHP interpreter itself, fixed on 22 October 2026 in 8.2.35, 8.3.36, 8.4.27 and 8.5.12. Every build below those numbers is being probed.'
  },
  {
    icon: Boxes,
    title: 'The quiet win: a webshell',
    body: 'When an attack lands, it lands quietly. One file in an upload directory, executing whatever its owner sends it. It looks like any other PHP file until you read it and correlate it with the access log.'
  }
];

const detections = [
  {
    title: 'Webshell scanning with ban correlation',
    body: 'Every sniff pass reads PHP files in your web roots and scores them: request input reaching eval or system, eval of decoded data, markers of known shell families. A flagged file is an alert; the request that drives it from the access log is what gets banned.'
  },
  {
    title: 'PHP2Shell version check',
    body: 'Which PHP builds predate 8.2.35, 8.3.36, 8.4.27 or 8.5.12, on the host and inside every running container, from package databases and the official images’ own PHP_VERSION. Distribution packages get a "check your vendor" alert, because backports keep the old version number.'
  },
  {
    title: 'PHP2Shell attempt bans',
    body: 'The exploit’s footprint is a request that runs PHP out of memory while it is still being parsed. Apache logs it as in Unknown on line 0 with the client address; behind nginx, php-fpm dies and nginx logs the dead upstream. Both lines feed the ban engine.'
  },
  {
    title: 'Worker crash watch',
    body: 'php-fpm and Apache workers dying repeatedly on SIGSEGV, SIGBUS or SIGABRT raise an alert.'
  },
  {
    title: 'SSH and login brute force',
    body: 'The same pattern fail2ban users know: repeated failures, threshold, temporary ban. Container logs are discovered on their own.'
  }
];

const limits = [
  'It does not patch your code or your interpreter. Upgrading PHP and your dependencies stays your job; the free PHP2Shell check tells you where the patch belongs.',
  'The ban flags requests after they happen. Treat it as a backstop for scanners and repeat attempts, not a promise about a first, fast request.',
  'Bans are IPv4 only today. If your traffic is IPv6-heavy, that matters.',
  'It reads the logs it is pointed at. Host logs not listed in STACKDOG_LOG_SOURCES are invisible to it.'
];

export const metadata: Metadata = {
  title: 'Security for AI-Built Startups: Surviving the First Weeks',
  description:
    'Apps built with AI ship in days; the security operations layer does not. What early attacks look like on a fresh server, and how StackdogApp covers webshells, PHP2Shell and brute force without a single hand-written rule.',
  keywords: [
    'AI-built app security',
    'startup server security',
    'webshell detection',
    'PHP2Shell',
    'fail2ban alternative',
    'StackdogApp'
  ],
  alternates: {
    canonical: PAGE_PATH
  },
  openGraph: {
    title: 'Security for AI-Built Startups — StackdogApp',
    description:
      'The code arrives in days. The attacks arrive too. What early traffic looks like and how to cover it without writing detection rules.',
    url: getSiteUrl() + PAGE_PATH
  },
  twitter: {
    title: 'Security for AI-Built Startups — StackdogApp',
    description:
      'The code arrives in days. The attacks arrive too. What early traffic looks like and how to cover it.'
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

export default function AiBuiltStartupSecurityPage() {
  return (
    <main>
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{
          __html: toJsonLd(
            buildDocsStructuredData({
              title: 'Security for AI-Built Startups: Surviving the First Weeks',
              description:
                'What early attacks look like on a server hosting an AI-built app, and how StackdogApp ships the detection layer instead of asking founders to write it.',
              url: getSiteUrl() + PAGE_PATH,
              about: ['AI-built apps', 'Startup security', 'Webshell detection', 'PHP2Shell'],
              sections: [
                'What early attacks look like',
                'Install the boring layer',
                'What it turns on for you',
                'What it does not do',
                'The first-weeks checklist'
              ]
            })
          )
        }}
      />

      <section className="section-shell pt-12 sm:pt-16">
        <div className="site-container">
          <div className="max-w-3xl">
            <span className="eyebrow">For founders shipping with AI</span>
            <h1 className="mt-6 text-balance text-4xl font-semibold tracking-tight text-white sm:text-5xl">
              Your app shipped in a weekend. Your server is under attack since Monday.
            </h1>
            <p className="mt-6 text-lg leading-8 text-slate-400">
              The most common way to ship a product now: an idea on Friday, an app built
              with AI over the weekend, live on a server by Monday. The code arrives in
              days. What usually does not arrive with it is the boring layer: log
              monitoring, a ban list for scanners, a plan for which interpreter versions
              run where. Those were never the fun parts. They were what the security
              review, the ops person, or three painful weeks used to add.
            </p>
            <p className="mt-4 text-lg leading-8 text-slate-400">
              That gap is where the early attacks land. Not because AI writes worse code,
              but because the box serving your app is public from hour one and nobody is
              reading its logs. This is what that traffic looks like, and how to cover it
              without writing a single detection rule.
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
        id="early-attacks"
        className="section-shell scroll-mt-24 border-y border-slate-800/70 bg-slate-900/30"
      >
        <div className="site-container">
          <span className="eyebrow">What early attacks look like</span>
          <h2 className="section-heading mt-6">New deployments get three kinds of attention</h2>
          <div className="mt-10 grid gap-6 lg:grid-cols-2">
            {earlyAttacks.map((item) => {
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
          <p className="mt-8 max-w-3xl text-sm leading-7 text-slate-400">
            A favorite illustration of the gap: one harmless 24 MB form field sent to a
            stock php:8.3-apache container, no exploit code anywhere in it, and the error
            log recorded PHP dying in &quot;Unknown on line 0&quot; while parsing the
            request. A weekend app has forms, default memory limits, and nothing watching
            that line.
          </p>
        </div>
      </section>

      <section id="install" className="section-shell scroll-mt-24">
        <div className="site-container">
          <span className="eyebrow">Install the boring layer</span>
          <h2 className="section-heading mt-6">Five minutes, no detection rules to write</h2>
          <p className="section-copy">
            StackdogApp ships the detections instead of asking you to write them. Install
            it before you announce the product.
          </p>
          <div className="mt-10 grid grid-cols-1 gap-6 lg:grid-cols-2">
            <div className="space-y-6">
              <CodeSample code={installCommand} label="Install" />
              <CodeSample code={verifyCommand} label="Verify it is watching" />
            </div>
            <CodeSample code={envSnippet} label="Settings that matter first" />
          </div>
          <div className="mt-8 max-w-3xl space-y-4 text-sm leading-7 text-slate-400">
            <p>
              Two things matter in the settings. Web roots are where shells get dropped,
              so list every docroot you serve. And bans are read from log lines, so host
              web server logs must be listed in <code>STACKDOG_LOG_SOURCES</code>;
              container logs are discovered on their own.
            </p>
            <p>
              Set the ban policy before you need it. Five flagged requests from one
              address within five minutes is a ban; one stray request never bans anyone.
              Bans lift by themselves after 30 minutes, so a mistake costs half an hour,
              not a customer. Put anything in the allowlist whose ban would take you
              down: office and VPN addresses, uptime monitors, load balancers. Private
              and local addresses are never banned in the first place.
            </p>
            <p>
              Then verify: drop a harmless test file into a web root, watch the alert
              arrive, remove it. If nothing arrives, check the log paths first. The full
              walkthrough lives in the{' '}
              <Link href="/php-shell-quickstart" className="text-cyan-300 hover:text-cyan-200">
                quick start
              </Link>
              .
            </p>
          </div>
        </div>
      </section>

      <section
        id="detections"
        className="section-shell scroll-mt-24 border-y border-slate-800/70 bg-slate-900/30"
      >
        <div className="site-container">
          <span className="eyebrow">What it turns on for you</span>
          <h2 className="section-heading mt-6">The detection layer, already written</h2>
          <div className="mt-10 space-y-6">
            {detections.map((item) => (
              <div key={item.title} className="panel p-6">
                <h3 className="text-lg font-semibold text-white">{item.title}</h3>
                <p className="mt-3 text-sm leading-7 text-slate-400">{item.body}</p>
              </div>
            ))}
          </div>
          <p className="mt-8 max-w-3xl text-sm leading-7 text-slate-400">
            Deeper detail for each of these:{' '}
            <Link href="/php-shell-detection" className="text-cyan-300 hover:text-cyan-200">
              PHP shell detection
            </Link>{' '}
            and{' '}
            <Link href="/fail2ban-alternative" className="text-cyan-300 hover:text-cyan-200">
              how the ban layer compares to fail2ban
            </Link>
            .
          </p>
        </div>
      </section>

      <section id="limits" className="section-shell scroll-mt-24">
        <div className="site-container">
          <span className="eyebrow">Honest limits</span>
          <h2 className="section-heading mt-6">What it does not do</h2>
          <p className="section-copy">
            A security tool that oversells changes what you do, and that is how incidents
            happen. So, plainly:
          </p>
          <div className="mt-8 max-w-3xl space-y-4">
            {limits.map((limit) => (
              <p key={limit} className="text-sm leading-7 text-slate-400">
                {limit}
              </p>
            ))}
          </div>
        </div>
      </section>

      <section
        id="checklist"
        className="section-shell scroll-mt-24 border-y border-slate-800/70 bg-slate-900/30"
      >
        <div className="site-container">
          <span className="eyebrow">The first-weeks checklist</span>
          <h2 className="section-heading mt-6">Before the launch post goes out</h2>
          <div className="mt-8 max-w-3xl space-y-4">
            {checklist.map((item) => (
              <p key={item} className="flex gap-3 text-sm leading-7 text-slate-300">
                <span className="mt-2 h-2 w-2 flex-shrink-0 rounded-full bg-cyan-400" />
                {item}
              </p>
            ))}
          </div>
          <p className="mt-8 max-w-3xl text-sm leading-7 text-slate-400">
            The code an AI writes for you is a product. The server it runs on is an asset
            under attack from day one. StackdogApp is the boring layer that notices and
            reacts while you keep building features.
          </p>
          <div className="mt-8">
            <Link
              href="/php-shell-quickstart"
              className="inline-flex items-center gap-2 rounded-full bg-cyan-500 px-6 py-3 text-sm font-semibold text-slate-950 transition hover:bg-cyan-400"
            >
              Get started
              <ArrowRight className="h-4 w-4" />
            </Link>
          </div>
        </div>
      </section>
    </main>
  );
}
