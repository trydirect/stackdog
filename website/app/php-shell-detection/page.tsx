import type { Metadata } from 'next';
import Link from 'next/link';
import { ArrowRight, FileCode2, Radar, ScrollText, TerminalSquare } from 'lucide-react';
import CopyButton from '@/components/CopyButton';
import { getSiteUrl } from '@/lib/config';
import { buildDocsStructuredData, toJsonLd } from '@/lib/structured-data';

const PAGE_PATH = '/php-shell-detection';

const layers = [
  {
    name: 'File content scan',
    status: 'Available',
    description:
      'Every sniff pass reads PHP files in your web roots and scores them for webshell code. Only new or changed files are read; the rest are checked by size and modification time.',
    icon: FileCode2
  },
  {
    name: 'Access-log correlation',
    status: 'Available',
    description:
      'Requests to flagged files, and POSTs to PHP under uploads/ URLs, are picked out of nginx, Apache and application access logs — with the client address that sent them.',
    icon: ScrollText
  },
  {
    name: 'Process execution (eBPF)',
    status: 'Planned',
    description:
      'Catching php-fpm or Apache spawning sh, curl or nc at the kernel level. This catches shells no signature knows. It is not shipped yet.',
    icon: Radar
  }
];

const signalRows = [
  ['Request input reaches execution', 'Strong', 'eval($_POST[...]), system($_GET[...]), assert($_REQUEST[...])'],
  ['eval of decoded data', 'Strong', 'eval(base64_decode(...)), eval(gzinflate(...))'],
  ['Request input called as a function', 'Strong', '$_GET[\'f\']($_GET[\'c\'])'],
  ['preg_replace with /e', 'Strong', 'preg_replace("/.*/e", $_POST[\'c\'], \'\')'],
  ['Backticks around request input', 'Strong', '`$_GET[cmd]`'],
  ['Known shell family', 'Strong', 'c99, r57, WSO, b374k, p0wny, FilesMan, Weevely, IndoXploit'],
  ['PHP in an upload directory', 'Medium', 'wp-content/uploads/2026/10/x.php'],
  ['Nested decoders', 'Medium', 'base64_decode(str_rot13(...))'],
  ['Request input written to a file', 'Medium', 'file_put_contents($f, $_POST[\'d\'])'],
  ['PHP inside a non-PHP upload', 'Weak', 'GIF89a<?php ... in avatar.gif'],
  ['Packed payload', 'Weak', 'A single run of 1,000+ base64 characters'],
  ['Errors and time limit switched off', 'Weak', 'error_reporting(0), set_time_limit(0)']
] as const;

const responseRows = [
  ['php.shell-file', 'A new or changed file scores 3 or more', 'Alert. High, or Critical at 5+.'],
  [
    'web.php-shell-access',
    'Any request to a flagged upload whose URL goes through uploads/; a request with parameters to a flagged file that is not a common entry point; a POST to PHP under an uploads/ URL',
    'Alert and an offense against the client IP. The IP is banned once it reaches the ban threshold.'
  ],
  [
    'php.shell-request',
    'A plain visit to a flagged page, or any request to a flagged common entry point such as index.php or wp-login.php. /images/, /files/ and /tmp/ URLs count as ordinary pages.',
    'Alert only, never a ban. Banning visitors of an infected page would ban its audience.'
  ]
] as const;

const php2shellRows = [
  [
    'vuln.php2shell',
    'A PHP build older than 8.2.35, 8.3.36, 8.4.27 or 8.5.12, or any 8.1 and older, on the host or in a running container',
    'Critical alert for upstream builds such as official php images. Medium "check your vendor" alert for distribution packages, which backport fixes without changing the version number.'
  ],
  [
    'php.worker-crash',
    'Three or more php-fpm or Apache workers dying on SIGSEGV, SIGBUS, SIGABRT or SIGILL in one log source within one pass. One or two per pass never alert, so a single flaky extension stays quiet.',
    'Alert. Repeated crashes are what attempts against PHP memory bugs leave behind.'
  ],
  [
    'web.php2shell-attempt',
    'A request that runs PHP out of memory before any script runs (Apache "in Unknown on line 0", or nginx "upstream sent unexpected FastCGI record" on a POST to php-fpm), or the public scanner user agent',
    'Alert and an offense per line. A client causing five within the ban window is banned in the same pass.'
  ]
] as const;

const envRows = [
  ['STACKDOG_PHPSHELL_ENABLED', 'true', 'Turn PHP shell detection on or off: both the file scan and the access-log detector.'],
  ['STACKDOG_PHPSHELL_PATHS', '/var/www', 'Host web roots to scan, comma-separated. Containers are found on their own.'],
  [
    'STACKDOG_PHPSHELL_CONTAINERS',
    'php,wordpress,drupal,joomla,laravel,magento,apache,httpd',
    'Name or image fragments that mark a PHP container. Containers with a mount at /var/www, /srv, /app or /usr/share/nginx/html are scanned whatever their name.'
  ],
  ['STACKDOG_HOST_ROOT', '/host', 'Where the host filesystem is mounted when Stackdog runs in Docker. Needed for host paths and container docroots.'],
  ['STACKDOG_PHPSHELL_SKIP_DIRS', 'vendor,node_modules,.git', 'Directory names never descended into.'],
  ['STACKDOG_PHPSHELL_MAX_FILE_BYTES', '2097152', 'Bytes read per file. Larger files are scored on their first 2 MB.'],
  ['STACKDOG_PHPSHELL_SIGNATURES', '/etc/stackdog/php-shell-signatures.json', 'Extra signatures in JSON, added to the built-in ones.'],
  ['STACKDOG_PHP_VERSION_CHECK_ENABLED', 'true', 'Alert on PHP builds older than the PHP2Shell fixes, on the host and in containers.']
] as const;

const composeSnippet = `services:
  stackdog:
    image: trydirect/stackdog:latest
    network_mode: host
    cap_add:
      - NET_ADMIN
    environment:
      DATABASE_URL: /data/stackdog.db
      STACKDOG_HOST_ROOT: /host
      STACKDOG_PHPSHELL_PATHS: /var/www
      STACKDOG_LOG_SOURCES: /var/log/nginx/access.log
    volumes:
      - stackdog-data:/data
      - /var/run/docker.sock:/var/run/docker.sock
      - /:/host:ro
    command: serve`;

const hostSnippet = `export STACKDOG_PHPSHELL_PATHS=/var/www
export STACKDOG_LOG_SOURCES=/var/log/nginx/access.log
stackdog serve`;

const signatureSnippet = `[
  {
    "id": "acme-shell",
    "description": "ACME shell marker",
    "pattern": "acme_shell_v\\\\d",
    "weight": "strong"
  }
]`;

const runbookSteps = [
  {
    title: 'Read the alert',
    body: 'A php.shell-file alert names the file as the workload sees it, the host or container it is on, the rules that matched, and the start of its SHA-256.'
  },
  {
    title: 'Check who is using it',
    body: 'stackdog firewall list shows addresses already banned for web.php-shell-access. Search the access log for the file name to see every client that requested it.'
  },
  {
    title: 'Remove it and find the way in',
    body: 'Stackdog never deletes or moves files. Take a copy for evidence, remove the shell, then look for how it got there: an upload form, an outdated plugin, a writable docroot, leaked credentials.'
  },
  {
    title: 'Release mistakes',
    body: 'If a ban hit someone it should not have, stackdog unban <ip> releases it, and STACKDOG_IP_BAN_ALLOWLIST keeps that address out of every future ban.'
  }
];

const faqEntries = [
  {
    question: 'Will it flag WordPress, Laravel or phpMyAdmin?',
    answer:
      'It should not. One keyword never flags a file: WordPress calls base64_decode and Composer calls proc_open. A file is flagged on the sum of its signals, and a strong signal means request input reaching code execution. vendor/ and node_modules/ are skipped by default.'
  },
  {
    question: 'Does Stackdog delete the shell?',
    answer:
      'No. Detection raises an alert and bans the clients driving the shell. Removing the file stays your decision, because a false positive that deleted a page would take part of a site down.'
  },
  {
    question: 'How fast is a ban?',
    answer:
      'Each sniff pass (30 seconds by default) records one offense per client. With the default threshold of 5 offenses in 5 minutes, an attacker who keeps using the shell is banned within a few minutes. The ban threshold, window and duration are the same STACKDOG_IP_BAN_* settings every other detector uses.'
  },
  {
    question: 'Which logs does it read?',
    answer:
      'Any access log Stackdog already sniffs: nginx and Apache combined format, plain "GET /path" lines, and actix-style "GET:/path" request dumps. Add your access log to STACKDOG_LOG_SOURCES if it is not discovered automatically.'
  },
  {
    question: 'What about shells baked into a container image?',
    answer:
      'For PHP containers, Stackdog also reads the docroot through the container overlay filesystem (overlay2 MergedDir) under the host mount, so files that are not on a volume are covered too.'
  }
];

export const metadata: Metadata = {
  title: 'PHP Webshell Detection',
  description:
    'Detect PHP webshells in host and Docker web roots, correlate them with access logs, and automatically ban the clients that drive them.',
  keywords: [
    'PHP webshell detection',
    'PHP shell scanner',
    'WordPress webshell',
    'c99 r57 WSO shell',
    'Docker PHP security',
    'Stackdog Security'
  ],
  alternates: {
    canonical: PAGE_PATH
  },
  openGraph: {
    title: 'PHP Webshell Detection with Stackdog',
    description:
      'Find PHP webshells in host and container web roots and ban the clients driving them.',
    url: getSiteUrl() + PAGE_PATH
  },
  twitter: {
    title: 'PHP Webshell Detection with Stackdog',
    description:
      'Find PHP webshells in host and container web roots and ban the clients driving them.'
  }
};

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

export default function PhpShellDetectionPage() {
  return (
    <main>
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{
          __html: toJsonLd(
            buildDocsStructuredData({
              title: 'PHP Webshell Detection with Stackdog',
              description:
                'How Stackdog finds PHP webshells in host and container web roots and bans the clients driving them.',
              url: getSiteUrl() + PAGE_PATH,
              about: ['PHP webshells', 'Web server security', 'Docker security', 'Automated IP banning'],
              sections: ['How it works', 'Signals', 'Response', 'PHP2Shell', 'Setup', 'Configuration', 'Incident runbook']
            })
          )
        }}
      />

      <section className="section-shell pt-12 sm:pt-16">
        <div className="site-container">
          <div className="max-w-3xl">
            <span className="eyebrow">PHP webshell detection</span>
            <h1 className="mt-6 text-balance text-4xl font-semibold tracking-tight text-white sm:text-5xl">
              Find PHP webshells and ban the clients driving them
            </h1>
            <p className="mt-6 text-lg leading-8 text-slate-400">
              A webshell is a PHP file that runs whatever its owner sends it: shell commands, database
              queries, file uploads, spam. It usually arrives through an upload form, an outdated plugin
              or a writable docroot, and it looks like any other PHP file. Stackdog reads your web roots
              on the host and in your containers, flags the files that execute request input, and bans
              the addresses that use them.
            </p>
            <div className="mt-8 flex flex-wrap items-center gap-4">
              <Link
                href="/php-shell-quickstart"
                className="inline-flex items-center gap-2 rounded-full bg-cyan-500 px-6 py-3 text-sm font-semibold text-slate-950 transition hover:bg-cyan-400"
              >
                Quick start
                <ArrowRight className="h-4 w-4" />
              </Link>
              <Link
                href="/docs"
                className="inline-flex items-center gap-2 rounded-full border border-slate-700 px-6 py-3 text-sm font-semibold text-slate-200 transition hover:border-cyan-400/50 hover:text-white"
              >
                Read the docs
              </Link>
            </div>
          </div>
        </div>
      </section>

      <section id="how-it-works" className="section-shell scroll-mt-24 border-y border-slate-800/70 bg-slate-900/30">
        <div className="site-container">
          <span className="eyebrow">How it works</span>
          <h2 className="section-heading mt-6">The file, the request, and (soon) the process</h2>
          <p className="section-copy">
            A file on disk names no attacker, so a flagged file is an alert. The request that drives
            it carries the client address, so that is what gets banned.
          </p>
          <div className="mt-10 grid gap-6 lg:grid-cols-3">
            {layers.map((layer) => {
              const Icon = layer.icon;
              const planned = layer.status === 'Planned';
              return (
                <article key={layer.name} className="panel p-6">
                  <div className="flex items-center justify-between gap-4">
                    <div className="inline-flex h-12 w-12 items-center justify-center rounded-2xl border border-cyan-500/20 bg-cyan-500/10 text-cyan-300">
                      <Icon className="h-5 w-5" />
                    </div>
                    <span
                      className={`rounded-full px-3 py-1 text-xs font-semibold ${planned ? 'border border-slate-700 text-slate-400' : 'border border-emerald-500/30 bg-emerald-500/10 text-emerald-300'}`}
                    >
                      {layer.status}
                    </span>
                  </div>
                  <h3 className="mt-5 text-xl font-semibold text-white">{layer.name}</h3>
                  <p className="mt-3 text-sm leading-7 text-slate-400">{layer.description}</p>
                </article>
              );
            })}
          </div>
        </div>
      </section>

      <section id="signals" className="section-shell scroll-mt-24">
        <div className="site-container">
          <span className="eyebrow">Signals</span>
          <h2 className="section-heading mt-6">Scored, never flagged on one keyword</h2>
          <p className="section-copy">
            WordPress calls <code>base64_decode</code>, Composer calls <code>proc_open</code>, test suites
            call <code>assert</code>. What marks a shell is request input reaching code execution, or
            code hiding what it executes. Strong signals score 3, medium 2, weak 1, and a file is
            flagged at 3. A PHP file in an upload directory on its own scores 2, because plugins put
            harmless <code>index.php</code> files there.
          </p>
          <div className="mt-10">
            <DataTable headers={['Signal', 'Weight', 'Example']} rows={signalRows} />
          </div>
        </div>
      </section>

      <section id="response" className="section-shell scroll-mt-24 border-y border-slate-800/70 bg-slate-900/30">
        <div className="site-container">
          <span className="eyebrow">Response</span>
          <h2 className="section-heading mt-6">Alert on the file, ban on the request</h2>
          <p className="section-copy">
            Bans pass through the same gate as every other Stackdog ban: the allowlist, protected local
            and container addresses, and the per-minute ceiling all apply. Stackdog never deletes or
            moves the file.
          </p>
          <div className="mt-10">
            <DataTable headers={['Finding', 'When', 'Action']} rows={responseRows} />
          </div>
        </div>
      </section>

      <section id="php2shell" className="section-shell scroll-mt-24">
        <div className="site-container">
          <span className="eyebrow">PHP2Shell</span>
          <h2 className="section-heading mt-6">CVE-2026-109618 and CVE-2026-109619: find what still needs upgrading</h2>
          <p className="section-copy">
            PHP2Shell is unauthenticated remote code execution in the PHP interpreter itself, so no
            file scan or log rule can fix it: the fix is upgrading PHP. Stackdog reads the PHP version
            on the host and in every running container, from the package database and from the{' '}
            <code>PHP_VERSION</code> variable of official images, and tells you which ones are behind.
            It watches for PHP workers that keep crashing, and it bans clients whose requests run PHP
            out of memory before any script runs, the step every known PHP2Shell variant relies on.
            The exploit can succeed in a few requests, so the ban mostly stops repeat attempts and
            scanners; upgrading stays the fix. Rare innocent causes exist (a giant form on a PHP with a
            tiny memory_limit, a buggy extension crashing php-fpm on an upload), which is why a ban
            takes five within five minutes from one address.
          </p>
          <div className="mt-10">
            <DataTable headers={['Finding', 'When', 'Action']} rows={php2shellRows} />
          </div>
          <p className="mt-6 text-sm leading-7 text-slate-400">
            Covered: Debian and Ubuntu (<code>php8.x-common</code>), Alpine (<code>php8x-common</code>) and
            official <code>php</code> images. RPM-based hosts are not read yet. Attempts are read from
            web server error logs: container logs on their own, host logs once listed in{' '}
            <code>STACKDOG_LOG_SOURCES</code>. A shell an attacker drops after getting in is still
            caught by the file scan above.
          </p>
        </div>
      </section>

      <section id="setup" className="section-shell scroll-mt-24 border-y border-slate-800/70 bg-slate-900/30">
        <div className="site-container">
          <span className="eyebrow">Setup</span>
          <h2 className="section-heading mt-6">Host web roots and PHP containers</h2>
          <p className="section-copy">
            Host paths come from <code>STACKDOG_PHPSHELL_PATHS</code>. PHP containers are found on their
            own, by name or image, or by a volume mounted at a docroot. Mounted docroots are read at
            their host source and docroots baked into the image through the overlay filesystem. Running
            in Docker, Stackdog reads both through a read-only mount of the host. For a plain server,
            the <Link href="/php-shell-quickstart" className="text-cyan-300 hover:text-cyan-200">quick start</Link>{' '}
            has the install command, recommended settings and a systemd unit.
          </p>
          <div className="mt-10 grid grid-cols-1 gap-6 lg:grid-cols-2">
            <CodeSample code={composeSnippet} label="Docker Compose" />
            <div className="space-y-6">
              <CodeSample code={hostSnippet} label="Binary on the host" />
              <div className="panel p-6">
                <div className="flex items-center gap-3">
                  <TerminalSquare className="h-5 w-5 text-cyan-300" />
                  <h3 className="text-lg font-semibold text-white">Make sure the access log is read</h3>
                </div>
                <p className="mt-3 text-sm leading-7 text-slate-400">
                  Bans come from access-log lines. Container logs are discovered automatically; add host
                  access logs such as <code>/var/log/nginx/access.log</code> to{' '}
                  <code>STACKDOG_LOG_SOURCES</code>.
                </p>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section id="configuration" className="section-shell scroll-mt-24">
        <div className="site-container">
          <span className="eyebrow">Configuration</span>
          <h2 className="section-heading mt-6">Settings</h2>
          <div className="mt-10">
            <DataTable headers={['Variable', 'Default / example', 'Purpose']} rows={envRows} />
          </div>
          <div className="mt-10 grid grid-cols-1 gap-6 lg:grid-cols-2">
            <div>
              <h3 className="text-xl font-semibold text-white">Your own signatures</h3>
              <p className="mt-3 text-sm leading-7 text-slate-400">
                Cover a new shell family without waiting for a release. Patterns are case-insensitive
                regular expressions; weights are <code>strong</code>, <code>medium</code> or{' '}
                <code>weak</code>. A file that fails to parse is reported in the log and the built-in
                signatures keep working.
              </p>
            </div>
            <CodeSample code={signatureSnippet} label="php-shell-signatures.json" />
          </div>
        </div>
      </section>

      <section id="runbook" className="section-shell scroll-mt-24 border-y border-slate-800/70 bg-slate-900/30">
        <div className="site-container">
          <span className="eyebrow">Incident runbook</span>
          <h2 className="section-heading mt-6">When a shell is found</h2>
          <ol className="mt-10 grid gap-6 md:grid-cols-2">
            {runbookSteps.map((step, index) => (
              <li key={step.title} className="panel p-6">
                <span className="text-sm font-semibold text-cyan-300">Step {index + 1}</span>
                <h3 className="mt-3 text-lg font-semibold text-white">{step.title}</h3>
                <p className="mt-3 text-sm leading-7 text-slate-400">{step.body}</p>
              </li>
            ))}
          </ol>
        </div>
      </section>

      <section id="faq" className="section-shell scroll-mt-24">
        <div className="site-container">
          <span className="eyebrow">FAQ</span>
          <h2 className="section-heading mt-6">Questions operators ask</h2>
          <div className="mt-10 grid grid-cols-1 gap-6 lg:grid-cols-2">
            {faqEntries.map((entry) => (
              <article key={entry.question} className="panel p-6">
                <h3 className="text-lg font-semibold text-white">{entry.question}</h3>
                <p className="mt-3 text-sm leading-7 text-slate-400">{entry.answer}</p>
              </article>
            ))}
          </div>
        </div>
      </section>
    </main>
  );
}
