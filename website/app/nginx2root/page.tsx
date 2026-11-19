import type { Metadata } from 'next';
import Link from 'next/link';
import { ArrowRight, Boxes, FileSearch, ShieldAlert, TerminalSquare } from 'lucide-react';
import CopyButton from '@/components/CopyButton';
import { getSiteUrl } from '@/lib/config';
import { buildDocsStructuredData, toJsonLd } from '@/lib/structured-data';

const PAGE_PATH = '/nginx2root';

const versionCommand = `# What is running, and on which track (odd minor = mainline, even = stable)
nginx -v 2>&1

# Distro packages backport fixes without bumping the upstream number:
# 1.26.3-1+deb12u3 can carry the fix while nginx -v still says 1.26.3.
dpkg -l nginx       # Debian / Ubuntu
rpm -q nginx        # RHEL / Alma / Rocky
apk info -e nginx   # Alpine

# Fixed: nginx 1.30.7 (stable) / 1.31.9 (mainline), NGINX Plus 37.0.8.1 / 37.3.0.1`;

const restartCommand = `# A reload is not a restart. Reload keeps the old binary answering.
sudo systemctl restart nginx

# Containers: pull the fixed image and re-create, don't reuse the old one
docker compose pull
docker compose up -d --force-recreate`;

const mitigationCommand = `# CVE-2026-123007 / CVE-2026-123633: HTTP/2 off
http2 off;                          # or drop http2 from the listen directives

# CVE-2026-121810: no QUIC listeners
# remove the quic/http3 listeners, or set http3 off

# CVE-2026-123634: fixed upstream groups
proxy_pass http://backend_group;    # not a variable, with SSI/mirror in play

# CVE-2026-113425: mail proxy off or fenced
# bind mail listeners to loopback, or firewall them to trusted networks

# Kernel step: block SCTP until the fix lands
echo 'install sctp /bin/false' > /etc/modprobe.d/zz-block-sctp.conf
rmmod sctp 2>/dev/null || true      # a rule only stops it loading`;

const iocCommand = `# Runs of nginx workers dying on memory faults
sudo journalctl -u nginx --since "-24h" | grep -i 'signal 11\\|segfault\\|worker process'

# Programs running as the nginx worker user (workers never exec anything)
ps -u www-data -o pid,ppid,lstart,cmd

# The kernel escalation path
grep sctp /proc/modules`;

const installCommand =
  'curl -fsSL https://raw.githubusercontent.com/trydirect/stackdog/main/install.sh | sudo bash';

const cveCards = [
  {
    id: 'CVE-2026-123633',
    name: 'HTTP/2 use-after-free while proxying',
    body: 'A use-after-free on the HTTP/2 proxy path, reached while nginx forwards requests to a backend when worker_connections is low. Turn HTTP/2 off on the frontend and the path closes.',
    mitigation: 'http2 off'
  },
  {
    id: 'CVE-2026-121810',
    name: 'HTTP/3 (QUIC) use-after-free while proxying',
    body: 'The same shape of bug on the HTTP/3 path: a use-after-free while proxying over QUIC. Separate code, separate fix, same class of end state.',
    mitigation: 'remove the quic/http3 listeners, or set http3 off'
  },
  {
    id: 'CVE-2026-123634',
    name: 'Resolver use-after-free',
    body: 'Triggered when proxy_pass builds its upstream from a variable and an SSI or mirror subrequest resolves the same name. The resolver frees a name the request still holds.',
    mitigation: 'point proxy_pass at a fixed upstream group'
  },
  {
    id: 'CVE-2026-113425',
    name: 'Mail proxy use-after-free',
    body: 'A use-after-free in the mail proxy, reached through auth_http. The smallest audience of the five, and the smallest excuse for leaving it on.',
    mitigation: 'bind mail listeners to loopback, or firewall them to trusted networks'
  }
];

const iocs = [
  {
    icon: TerminalSquare,
    title: 'Programs spawned by the nginx worker',
    body: 'nginx workers serve requests; they never execute anything. A process whose parent is a worker is the end state of a successful exploit, and the clearest signal you have.'
  },
  {
    icon: ShieldAlert,
    title: 'Runs of worker crashes',
    body: 'One segfault is a flaky module. Workers dying repeatedly on signal 11 (SIGSEGV) and other memory faults is what heap-grooming attempts against these bugs leave behind.'
  },
  {
    icon: Boxes,
    title: 'HTTP/2 connections that grow while the log stays flat',
    body: 'The exploit runs in control frames that are never logged as requests. Long-lived HTTP/2 connections whose received bytes keep climbing while the access log records nothing are the network signature.'
  },
  {
    icon: FileSearch,
    title: 'SCTP socket activity',
    body: 'SCTP sockets opened by nginx or from inside a container, followed by that container reaching the host kernel, is the escalation step of the chain in motion.'
  }
];

const stackdogDetections = [
  [
    'vuln.nginx2root',
    'Exposure detection. Flags nginx builds older than the fixes whose configuration actually reaches one of the five CVEs: it reads HTTP/2, HTTP/3, mail proxy and proxy_pass + SSI/mirror reachability from the config on the host and inside running containers, and reads NGINX_VERSION from official images and package databases. It follows nginx\u2019s two version tracks, names the CVE, and prints the exact mitigation - set http2 off, drop the quic listeners, and so on - next to the upgrade it does not replace.'
  ],
  [
    'nginx.worker-crash',
    'Crash detection. Alerts on a run of nginx workers dying on memory faults (SIGSEGV and friends), which is what heap-grooming attempts against the memory-corruption bugs leave behind.'
  ],
  [
    'nginx.http2-spray',
    'Network footprint. A workload-level heuristic that flags a container whose inbound bytes grew while its logged request count stayed small - what an HTTP/2 heap spray looks like, because its control frames are never logged. A review signal, not a certainty: a large upload can look similar, so it is read alongside the crash and RCE detections.'
  ],
  [
    'web.worker-exec',
    'RCE detection. Alerts when a web-server worker - nginx, Apache or php-fpm - executes a program, watched through eBPF syscall monitoring. Web workers do not run programs, so this is the RCE end state.'
  ],
  [
    'kernel.sctp-socket',
    'Kernel escalation in motion. Alerts when a web-server worker or a container process opens an SCTP socket, the first step of the unpatched kernel root-escalation, watched through eBPF syscall monitoring.'
  ],
  [
    'kernel.sctp-exposed',
    'Kernel escalation exposure. Alerts when the Linux SCTP kernel module is loaded and reachable - the unpatched root-escalation step of the chain - and recommends blocking it with install sctp /bin/false when you do not need it.'
  ],
  [
    'container.posture-risk',
    'Container posture. Flags privileged, host-network and host-PID containers - nginx inside one of those turns this chain straight into host root - and Stackdog can quarantine a compromised container while you investigate.'
  ]
] as const;

const faqStyleNotes = [
  {
    title: 'It detects, it does not patch',
    body: 'Upgrading nginx is the fix. Everything Stackdog does here is visibility: which builds are exposed, which features make them exposed, and whether anyone has used the exposure yet.'
  },
  {
    title: 'Version findings mean "a fix is missing"',
    body: 'Not "you are exploitable". Distributions backport fixes without changing the upstream version number, so every version finding says to check your vendor\u2019s advisory before you panic.'
  },
  {
    title: 'No client address, no ban',
    body: 'The exploit\u2019s control frames are not logged as requests, so none of these detectors ever bans an address. Bans stay where logs carry the client: webshells, PHP2Shell attempts, SSH and login brute force. Bans are IPv4-only today.'
  }
];

export const metadata: Metadata = {
  title: 'CVE-2026-123007: NGINX2Root and How to Protect Your Servers and Containers',
  description:
    'NGINX2Root is five nginx memory-corruption bugs (CVE-2026-123007 and four more) plus an unpatched kernel SCTP escalation to root. The fixed releases, why a reload is not enough, the IOCs, and how Stackdog detects every step.',
  keywords: [
    'NGINX2Root',
    'CVE-2026-123007',
    'nginx vulnerability',
    'HTTP/2 RCE',
    'nginx container escape',
    'Stackdog Security'
  ],
  alternates: {
    canonical: PAGE_PATH
  },
  openGraph: {
    title: 'CVE-2026-123007: NGINX2Root and How to Protect Your Servers and Containers | StackdogApp',
    description:
      'Five nginx bugs, one unpatched kernel escalation, and a reload that fixes nothing. What to change today and where Stackdog sees each step.',
    url: getSiteUrl() + PAGE_PATH
  },
  twitter: {
    title: 'CVE-2026-123007: NGINX2Root and How to Protect Your Servers and Containers | StackdogApp',
    description:
      'Five nginx bugs, one unpatched kernel escalation, and a reload that fixes nothing. What to change today and where Stackdog sees each step.'
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

export default function Nginx2RootPage() {
  return (
    <main>
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{
          __html: toJsonLd(
            buildDocsStructuredData({
              title: 'CVE-2026-123007: NGINX2Root and How to Protect Your Servers and Containers',
              description:
                'Five nginx memory-corruption bugs (CVE-2026-123007 and four more), an unpatched kernel SCTP escalation to root, the fixed releases, the IOCs, and how Stackdog detects each step.',
              url: getSiteUrl() + PAGE_PATH,
              about: ['NGINX2Root', 'CVE-2026-123007', 'nginx security', 'Container escape'],
              sections: [
                'The chain',
                'The five CVEs',
                'The escalation',
                'Fixed releases',
                'What the attacks leave behind',
                'What you should do right now',
                'How Stackdog detects it',
                'Beyond NGINX2Root',
                'Honest limits'
              ]
            })
          )
        }}
      />

      <section className="section-shell pt-12 sm:pt-16">
        <div className="site-container">
          <div className="max-w-3xl">
            <span className="eyebrow">Vulnerability brief</span>
            <h1 className="mt-6 text-balance text-4xl font-semibold tracking-tight text-white sm:text-5xl">
              CVE-2026-123007: NGINX2Root and how to protect your servers and containers
            </h1>
            <p className="mt-6 text-lg leading-8 text-slate-400">
              On 18 November 2026, Xint (Theori) disclosed five memory-corruption vulnerabilities in
              nginx. The worst of them, CVE-2026-123007, is unauthenticated remote code execution
              over plain HTTPS. A separate bug in the Linux kernel&apos;s SCTP stack, still
              unpatched, turns that code execution into root - including from inside a Docker
              container onto the host kernel. Together they are being called NGINX2Root: nginx to
              root.
            </p>
            <p className="mt-4 text-lg leading-8 text-slate-400">
              The nginx fixes are out, and upgrading is the real fix. But a configuration reload
              does not apply them, the attack traffic never appears in your access log, and the
              escalation step has no patch at all yet. Here is what the chain is, what to change
              today, and where Stackdog sees each step of it.
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
                href="#what-to-do"
                className="inline-flex items-center gap-2 rounded-full border border-slate-700 px-6 py-3 text-sm font-semibold text-slate-200 transition hover:border-cyan-400/50 hover:text-white"
              >
                What you should do right now
              </Link>
            </div>
          </div>
        </div>
      </section>

      <section
        id="the-chain"
        className="section-shell scroll-mt-24 border-y border-slate-800/70 bg-slate-900/30"
      >
        <div className="site-container">
          <span className="eyebrow">The chain</span>
          <h2 className="section-heading mt-6">Five nginx bugs and one kernel bug</h2>
          <div className="mt-6 max-w-3xl space-y-4 text-sm leading-7 text-slate-400">
            <p>
              NGINX2Root is two disclosures that meet in the middle. The first is a set of five
              memory-corruption bugs in nginx itself, all fixed on 18 November. The second is a
              use-after-free in the Linux kernel&apos;s SCTP implementation, which is not fixed:
              it escalates whatever code runs as the nginx worker to root, and it works across the
              Docker boundary, from a compromised container out to the host kernel.
            </p>
            <p>
              The nginx bugs are only reachable when the feature that contains them is enabled.
              HTTP/2 on a listener puts CVE-2026-123007 on your public interface; a mail proxy
              block puts CVE-2026-113425 there. That is why a version number alone is a poor
              answer to &quot;am I exposed&quot;, and why the configuration matters as much as the
              build.
            </p>
            <p>
              The end state of the first stage is deliberately unglamorous: the payload runs as
              the nginx worker process. No dropped webshell, no new service - just the process
              that was already serving your traffic, now executing someone else&apos;s code.
            </p>
          </div>
        </div>
      </section>

      <section id="the-five-cves" className="section-shell scroll-mt-24">
        <div className="site-container">
          <span className="eyebrow">The five CVEs</span>
          <h2 className="section-heading mt-6">What each bug needs to be reachable</h2>
          <div className="panel mt-10 max-w-3xl border-cyan-500/30 p-6">
            <div className="flex flex-wrap items-center gap-3">
              <h3 className="break-words font-mono text-sm font-semibold text-cyan-200">
                CVE-2026-123007
              </h3>
              <span className="eyebrow">The worst of the five</span>
            </div>
            <p className="mt-4 text-base font-semibold text-white">
              HTTP/2 flow-control integer underflow → out-of-bounds heap read/write
            </p>
            <div className="mt-3 space-y-3 text-sm leading-7 text-slate-400">
              <p>
                An integer underflow in HTTP/2 flow control opens an out-of-bounds heap read and
                write, and from there unauthenticated remote code execution. It needs nothing but
                HTTP/2 over TLS on a listener: no authentication, no special request, no
                misconfiguration. Every nginx back to 1.9.5 is affected. A working proof of
                concept is public, and Rapid7&apos;s reproduction pushes roughly 128 GB of HTTP/2
                traffic at the target to groom the heap and brute-force ASLR before the payload
                lands - as the nginx worker process.
              </p>
            </div>
            <p className="mt-4 text-sm leading-7 text-slate-300">
              Until you upgrade:{' '}
              <code>set http2 off, or remove http2 from the listen directives</code>
            </p>
          </div>
          <div className="mt-6 grid gap-6 lg:grid-cols-2">
            {cveCards.map((cve) => (
              <article key={cve.id} className="panel p-6">
                <h3 className="break-words font-mono text-sm font-semibold text-cyan-200">
                  {cve.id}
                </h3>
                <p className="mt-2 text-base font-semibold text-white">{cve.name}</p>
                <p className="mt-3 text-sm leading-7 text-slate-400">{cve.body}</p>
                <p className="mt-4 text-sm leading-7 text-slate-300">
                  Until you upgrade: <code>{cve.mitigation}</code>
                </p>
              </article>
            ))}
          </div>
          <p className="mt-8 max-w-3xl text-sm leading-7 text-slate-400">
            All five are fixed in the same releases - which is convenient, because the hard part
            was never the patch. It was noticing whether the patch is actually running.
          </p>
        </div>
      </section>

      <section
        id="the-escalation"
        className="section-shell scroll-mt-24 border-y border-slate-800/70 bg-slate-900/30"
      >
        <div className="site-container">
          <span className="eyebrow">The escalation</span>
          <h2 className="section-heading mt-6">From nginx worker to root, and out of the container</h2>
          <div className="mt-6 max-w-3xl space-y-4 text-sm leading-7 text-slate-400">
            <p>
              The name of the chain comes from its second half. Once code runs as the nginx
              worker, the unpatched SCTP use-after-free in the Linux kernel takes it the rest of
              the way: to root. And because the kernel is shared, the boundary a Docker container
              is supposed to provide does not help - the escalation works from inside a container
              out to the host kernel. A &quot;just a web container&quot; nginx is one kernel bug
              away from being your whole machine.
            </p>
            <p>
              The kernel bug has no fix yet. The only mitigation is to stop the module it lives in
              from loading at all.
            </p>
          </div>
          <div className="panel mt-8 flex gap-4 border-amber-500/30 p-6">
            <ShieldAlert className="mt-1 h-5 w-5 flex-none text-amber-300" />
            <p className="text-sm leading-7 text-slate-300">
              On hosts that do not need SCTP, block it until the kernel fix lands:{' '}
              <code>echo &apos;install sctp /bin/false&apos; &gt; /etc/modprobe.d/zz-block-sctp.conf</code>
              . If the module is loaded already, a rule only stops it loading - run{' '}
              <code>rmmod sctp</code> (or reboot) to drop it.
            </p>
          </div>
        </div>
      </section>

      <section id="fix" className="section-shell scroll-mt-24">
        <div className="site-container">
          <span className="eyebrow">Fixed releases</span>
          <h2 className="section-heading mt-6">Upgrade, then restart - a reload fixes nothing</h2>
          <div className="mt-6 max-w-3xl space-y-4 text-sm leading-7 text-slate-400">
            <p>
              The nginx bugs are fixed in <code>nginx 1.30.7</code> (stable) and{' '}
              <code>nginx 1.31.9</code> (mainline), and in NGINX Plus 37.0.8.1 and 37.3.0.1. nginx
              keeps two live tracks - odd minors are mainline, even minors are stable - and a
              version is fixed when it reaches the fix on its own track. 1.31.0 sorts above
              1.30.7 and is still vulnerable.
            </p>
            <p>
              Distribution packages complicate the picture in both directions. Debian, RHEL and
              Alpine builds can carry a backported fix while <code>nginx -v</code> still prints
              the old upstream number, so check your package version and your vendor&apos;s
              advisory before concluding anything from the banner.
            </p>
          </div>
          <div className="mt-10 grid grid-cols-1 gap-6 lg:grid-cols-2">
            <CodeSample code={versionCommand} label="Check what is running" />
            <CodeSample code={restartCommand} label="Then restart" />
          </div>
          <div className="panel mt-10 flex gap-4 border-amber-500/30 p-6">
            <ShieldAlert className="mt-1 h-5 w-5 flex-none text-amber-300" />
            <p className="text-sm leading-7 text-slate-300">
              A reload does not fix this. <code>nginx -s reload</code> and{' '}
              <code>systemctl reload nginx</code> swap the configuration but keep the old code in
              every running worker - the vulnerable binary is still what answers connections.
              Restart the service, or re-create your containers from a fixed image. An
              &quot;updated&quot; nginx that was only reloaded is still a vulnerable nginx.
            </p>
          </div>
        </div>
      </section>

      <section
        id="iocs"
        className="section-shell scroll-mt-24 border-y border-slate-800/70 bg-slate-900/30"
      >
        <div className="site-container">
          <span className="eyebrow">What the attacks leave behind</span>
          <h2 className="section-heading mt-6">Why your access log stays quiet</h2>
          <p className="section-copy">
            HTTP/2 control frames are not logged as requests, so this attack produces no entries
            to grep for. The exploit never asks your server anything the log would remember. What
            it does leave behind is process and memory behaviour, and one network pattern.
          </p>
          <div className="mt-10 grid gap-6 md:grid-cols-2">
            {iocs.map((ioc) => {
              const Icon = ioc.icon;
              return (
                <article key={ioc.title} className="panel p-6">
                  <div className="inline-flex h-12 w-12 items-center justify-center rounded-2xl border border-cyan-500/20 bg-cyan-500/10 text-cyan-300">
                    <Icon className="h-5 w-5" />
                  </div>
                  <h3 className="mt-4 text-lg font-semibold text-white">{ioc.title}</h3>
                  <p className="mt-3 text-sm leading-7 text-slate-400">{ioc.body}</p>
                </article>
              );
            })}
          </div>
          <div className="mt-10 max-w-3xl">
            <CodeSample code={iocCommand} label="Look for the signs" />
          </div>
        </div>
      </section>

      <section id="what-to-do" className="section-shell scroll-mt-24">
        <div className="site-container">
          <span className="eyebrow">Act now</span>
          <h2 className="section-heading mt-6">What you should do right now</h2>
          <ol className="mt-10 space-y-14">
            <Step number={1} title="Upgrade nginx, then restart it" code={restartCommand} label="Restart, not reload">
              <p>
                1.30.7 on the stable track, 1.31.9 on mainline, or your vendor&apos;s fixed build
                (NGINX Plus 37.0.8.1 / 37.3.0.1). Then restart the binary or re-create your
                containers - a configuration reload leaves the vulnerable code in place.
              </p>
            </Step>
            <Step number={2} title="No upgrade window yet? Turn the features off" code={mitigationCommand} label="Interim mitigations">
              <p>
                Each of the five needs an enabled feature. HTTP/2 off closes two of them, dropping
                QUIC listeners a third, a fixed upstream group the fourth, and fencing the mail
                proxy the fifth. Blocking the SCTP module is the only move you have against the
                kernel step.
              </p>
              <p>
                These are lossy - no HTTP/2 means no HTTP/2 - so treat them as the bridge to the
                upgrade, not the destination.
              </p>
            </Step>
            <Step number={3} title="Check whether it has been used" code={iocCommand} label="IOC sweep">
              <p>
                Runs of nginx workers dying on memory faults, programs running as the worker user,
                and SCTP socket activity are the three tells above. If a worker has spawned
                anything, treat the host or container as compromised: isolate it and rebuild from
                a fixed image rather than cleaning it.
              </p>
            </Step>
            <Step number={4} title="Keep watching" code={installCommand} label="Install StackdogApp">
              <p>
                The exposure comes back every time an image is pulled, a config is templated, or
                a container is scheduled. Stackdog keeps answering both questions continuously:
                is a reachable, vulnerable nginx present, and has anyone used it.
              </p>
            </Step>
          </ol>
        </div>
      </section>

      <section
        id="how-stackdog-helps"
        className="section-shell scroll-mt-24 border-y border-slate-800/70 bg-slate-900/30"
      >
        <div className="site-container">
          <span className="eyebrow">How Stackdog helps</span>
          <h2 className="section-heading mt-6">Detection for every step of the chain</h2>
          <p className="section-copy">
            Stackdog is a Rust-based, real-time threat detection and automated response platform
            for Docker containers and Linux servers - a modern fail2ban with eyes on the kernel
            and the container runtime. It does not patch anything; upgrading nginx is the fix.
            What it does is answer, continuously and without network scanning, the two questions
            this chain raises: is a vulnerable nginx reachable, and has anyone used it?
          </p>
          <div className="mt-10 grid grid-cols-1 gap-4 md:grid-cols-2">
            {stackdogDetections.map(([detector, body]) => (
              <article key={detector} className="panel p-5">
                <h3 className="break-words font-mono text-sm font-semibold text-cyan-200">
                  {detector}
                </h3>
                <p className="mt-2 text-sm leading-7 text-slate-400">{body}</p>
              </article>
            ))}
          </div>
          <p className="mt-8 max-w-3xl text-sm leading-7 text-slate-400">
            The exposure check alone is worth the install: it reads HTTP/2, HTTP/3, mail proxy and{' '}
            <code>proxy_pass</code> + SSI/mirror reachability from the nginx configuration on the
            host and inside every running container, so it names the CVEs that apply to{' '}
            <em>your</em> config - and the exact mitigation for each - instead of a generic
            &quot;upgrade nginx&quot;.
          </p>
        </div>
      </section>

      <section id="beyond" className="section-shell scroll-mt-24">
        <div className="site-container">
          <span className="eyebrow">Beyond NGINX2Root</span>
          <h2 className="section-heading mt-6">The rest of the month, and the ones after</h2>
          <div className="mt-6 max-w-3xl space-y-4 text-sm leading-7 text-slate-400">
            <p>
              This is the third serious event since October, and the pattern is always the same:
              disclosure, automated exploitation within hours, and a fix that has to reach every
              build you actually run. The nginx detectors sit next to the rest of the stack, which
              is built for that pattern.
            </p>
            <p>
              <code>vuln.cve-watch</code> matches every installed package on the host and inside
              containers against OSV and CISA&apos;s exploited-vulnerability catalog, so CVEs that
              do not get a dedicated detector still get flagged.{' '}
              <Link href="/php2shell-check" className="text-cyan-300 hover:text-cyan-200">
                PHP2Shell
              </Link>{' '}
              (CVE-2026-109618, CVE-2026-109619) is covered end to end: exposed PHP builds, PHP
              worker crashes, and the exploit&apos;s own footprint.{' '}
              <Link href="/sshole-check" className="text-cyan-300 hover:text-cyan-200">
                SSHole
              </Link>{' '}
              (CVE-2026-123158) likewise. Where a client address is available - webshells, brute
              force, the PHP2Shell attempt footprint - the ban engine acts on it fail2ban-style,
              firewall rule reconciled against its own database every pass.{' '}
              <Link href="/fail2ban-alternative" className="text-cyan-300 hover:text-cyan-200">
                The comparison has its own page
              </Link>
              .
            </p>
            <p>
              One honest caveat for NGINX2Root itself: because the control frames are never
              logged, there is no client address to ban. This chain is a detection problem, not a
              banning problem.
            </p>
          </div>
        </div>
      </section>

      <section
        id="limits"
        className="section-shell scroll-mt-24 border-y border-slate-800/70 bg-slate-900/30"
      >
        <div className="site-container">
          <span className="eyebrow">Honest limits</span>
          <h2 className="section-heading mt-6">What this does not do</h2>
          <div className="mt-6 max-w-3xl space-y-4 text-sm leading-7 text-slate-400">
            {faqStyleNotes.map((note) => (
              <div key={note.title}>
                <h3 className="text-lg font-semibold text-white">{note.title}</h3>
                <p className="mt-2">{note.body}</p>
              </div>
            ))}
            <p>
              Happy to answer questions about the detection side. And if you have seen this chain
              in your own logs - or seen it miss your logs entirely - we genuinely want to hear
              about it.{' '}
              <Link href="/contact" className="text-cyan-300 hover:text-cyan-200">
                Contact us
              </Link>
              .
            </p>
          </div>
        </div>
      </section>

      <section id="install" className="section-shell scroll-mt-24">
        <div className="site-container">
          <span className="eyebrow">Install today</span>
          <h2 className="section-heading mt-6">One command, then it watches</h2>
          <div className="mt-10 max-w-3xl">
            <CodeSample code={installCommand} label="Install" />
          </div>
          <p className="mt-6 max-w-3xl text-sm leading-7 text-slate-400">
            <code>stackdog init</code> writes a starter config and every setting has a safe
            default, so it runs with nothing configured at all. Also on Homebrew (
            <code>brew install trydirect/tap/stackdog</code>) and cargo (
            <code>cargo install stackdog</code>). The full walkthrough - settings, systemd unit,
            a safe test - is on the{' '}
            <Link href="/php-shell-quickstart" className="text-cyan-300 hover:text-cyan-200">
              quick start page
            </Link>
            .
          </p>
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
