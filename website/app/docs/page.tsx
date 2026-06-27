import type { Metadata } from 'next';
import Link from 'next/link';
import { ArrowUpRight, ExternalLink } from 'lucide-react';
import CopyButton from '@/components/CopyButton';
import { getSiteUrl } from '@/lib/config';
import { buildDocsStructuredData, toJsonLd } from '@/lib/structured-data';

const installCurl =
  'curl -fsSL https://raw.githubusercontent.com/trydirect/stackdog/main/install.sh | sudo bash';
const installPinned =
  'curl -fsSL https://raw.githubusercontent.com/trydirect/stackdog/main/install.sh | sudo bash -s -- --version v0.2.2';
const installDocker = `docker run --rm -it \\
  --name stackdog \\
  --network host \\
  --cap-add=NET_ADMIN \\
  -e APP_HOST=0.0.0.0 \\
  -e APP_PORT=5000 \\
  -e DATABASE_URL=/data/stackdog.db \\
  -v stackdog-data:/data \\
  -v /var/run/docker.sock:/var/run/docker.sock \\
  trydirect/stackdog:latest`;
const installSource = `git clone https://github.com/trydirect/stackdog\ncd stackdog\ncargo run -- serve`;

const sidebarItems = [
  { href: '#getting-started', label: 'Getting Started' },
  { href: '#cli-reference', label: 'CLI Reference' },
  { href: '#rest-api', label: 'REST API Reference' },
  { href: '#configuration', label: 'Configuration' },
  { href: '#contributing', label: 'Contributing' }
];

const sniffOptions = [
  ['--once', 'Run a single scan or analysis pass, then exit.'],
  ['--consume', 'Archive logs to zstd and purge originals after processing.'],
  ['--output <DIR>', 'Output directory for consumed logs. Defaults to ./stackdog-logs/.'],
  ['--sources <PATHS>', 'Additional comma-separated log paths to monitor.'],
  ['--interval <SECS>', 'Polling interval in seconds. Defaults to 30.'],
  ['--ai-provider <PROVIDER>', 'AI backend: openai, ollama, or candle.'],
  ['--ai-model <MODEL>', 'AI model name such as gpt-4o-mini or llama3.'],
  ['--ai-api-url <URL>', 'OpenAI-compatible API endpoint, including local Ollama.'],
  ['--slack-webhook <URL>', 'Slack incoming webhook for alert delivery.'],
  ['--webhook-url <URL>', 'Generic webhook target for alerts.'],
  ['--smtp-host <HOST>', 'SMTP host for email notifications.'],
  ['--smtp-port <PORT>', 'SMTP port for email notifications.'],
  ['--smtp-user <USER>', 'SMTP username or sender address.'],
  ['--smtp-password <PASS>', 'SMTP password.'],
  ['--email-recipients <EMAILS>', 'Comma-separated email recipients.']
] as const;

const apiRows = [
  ['GET', '/api/security/status', 'Live security posture and service health.'],
  ['GET', '/api/threats', 'Threat inventory and current detections.'],
  ['GET', '/api/alerts', 'Alert list for analysts and dashboards.'],
  ['GET', '/api/containers', 'Container inventory and runtime state.'],
  ['GET', '/api/logs/sources', 'Registered log sources for sniffing.'],
  ['GET', '/api/logs/summaries', 'AI-generated log summaries and findings.'],
  ['WS', '/ws', 'Real-time event stream over WebSocket.']
] as const;

const envRows = [
  ['APP_HOST', '0.0.0.0', 'HTTP host binding for stackdog serve.'],
  ['APP_PORT', '5000', 'HTTP API port.'],
  ['DATABASE_URL', 'stackdog.db', 'SQLite database file path.'],
  ['RUST_BACKTRACE', 'full', 'Verbose Rust backtraces for diagnostics.'],
  ['STACKDOG_SERVE_SNIFF_ENABLED', 'true', 'Enable background sniffing while the API server is running.'],
  ['STACKDOG_LOG_SOURCES', '/var/log/syslog,/var/log/auth.log', 'Additional log files to include in sniff mode.'],
  ['STACKDOG_SNIFF_INTERVAL', '30', 'Sniff polling interval in seconds.'],
  ['STACKDOG_AI_PROVIDER', 'openai', 'AI provider selection for log analysis.'],
  ['STACKDOG_AI_API_URL', 'http://localhost:11434/v1', 'API URL for OpenAI-compatible providers such as Ollama.'],
  ['STACKDOG_AI_MODEL', 'llama3', 'Model name for AI-assisted summarization.'],
  ['STACKDOG_SLACK_WEBHOOK_URL', 'https://hooks.slack.com/...', 'Slack alert destination.'],
  ['STACKDOG_WEBHOOK_URL', 'https://example.com/webhook', 'Generic webhook target.'],
  ['STACKDOG_IP_BAN_ENABLED', 'true', 'Enable automatic IP banning via iptables/nftables.'],
  ['STACKDOG_IP_BAN_MAX_RETRIES', '5', 'Offense count before an IP is banned.'],
  ['STACKDOG_IP_BAN_BAN_TIME_SECS', '1800', 'How long (seconds) an IP stays banned. Default 30 min.'],
  ['STACKDOG_IP_BAN_FIND_TIME_SECS', '300', 'Lookback window (seconds) for counting offenses.'],
  ['STACKDOG_NOTIFICATION_MIN_SEVERITY', 'info', 'Minimum severity for alert notifications. Options: info, low, medium, high, critical.'],
  ['STACKDOG_NOTIFY_IP_BAN_ACTIONS', 'true', 'Send notifications when an IP is banned or released.']
] as const;

export const metadata: Metadata = {
  title: 'Docs',
  description:
    'Read the Stackdog Security documentation for installation, CLI usage, REST API endpoints, and runtime configuration.',
  keywords: ['Stackdog docs', 'stackdog CLI', 'stackdog API', 'container security docs'],
  alternates: {
    canonical: '/docs'
  },
  openGraph: {
    title: 'Stackdog Security Docs',
    description:
      'Install Stackdog, run the CLI, integrate the API, and configure alerting and AI analysis.',
    url: getSiteUrl() + '/docs'
  },
  twitter: {
    title: 'Stackdog Security Docs',
    description:
      'Install Stackdog, run the CLI, integrate the API, and configure alerting and AI analysis.'
  }
};

function DocsTable({
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
                {row.map((cell) => (
                  <td key={cell} className="px-4 py-3 align-top leading-7">
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

export default function DocsPage() {
  return (
    <main className="section-shell pt-12 sm:pt-16">
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{
          __html: toJsonLd(
            buildDocsStructuredData({
              title: 'Stackdog Security Documentation',
              description:
                'CLI, API, configuration, and installation documentation for Stackdog Security.',
              url: getSiteUrl() + '/docs'
            })
          )
        }}
      />

      <div className="site-container">
        <div className="max-w-3xl">
          <span className="eyebrow">Product documentation</span>
          <h1 className="mt-6 text-4xl font-semibold tracking-tight text-white sm:text-5xl">
            Deploy Stackdog, run the CLI, and plug into the API
          </h1>
          <p className="mt-6 text-lg leading-8 text-slate-400">
            Everything you need to install Stackdog Security, start the API server, monitor logs,
            and integrate real-time detections into your workflows.
          </p>
        </div>

        <div className="mt-12 grid gap-10 lg:grid-cols-[260px_minmax(0,1fr)] xl:gap-16">
          <aside className="lg:sticky lg:top-24 lg:self-start">
            <nav className="panel p-4" aria-label="Documentation sections">
              <ul className="space-y-2 text-sm">
                {sidebarItems.map((item) => (
                  <li key={item.href}>
                    <a
                      href={item.href}
                      className="flex items-center justify-between rounded-xl px-3 py-2 text-slate-300 transition hover:bg-slate-800/70 hover:text-white"
                    >
                      <span>{item.label}</span>
                      <ArrowUpRight className="h-4 w-4 text-slate-500" />
                    </a>
                  </li>
                ))}
              </ul>
            </nav>
          </aside>

          <article className="space-y-14">
            <section id="getting-started" className="scroll-mt-24 space-y-8">
              <div>
                <h2 className="text-3xl font-semibold text-white">Getting Started</h2>
                <p className="mt-4 max-w-3xl text-base leading-8 text-slate-400">
                  Stackdog is designed for Docker containers and Linux servers. Use the installer for
                  a quick setup, the Docker image for disposable testing, or build from source when
                  you want to iterate locally.
                </p>
              </div>

              <div className="space-y-4">
                <h3 className="text-xl font-semibold text-white">Prerequisites</h3>
                <ul className="grid gap-3 text-sm leading-7 text-slate-300 sm:grid-cols-2">
                  <li className="panel p-4">Linux host or Docker environment</li>
                  <li className="panel p-4">Access to /var/run/docker.sock for Docker-aware features</li>
                  <li className="panel p-4">SQLite storage path for DATABASE_URL</li>
                  <li className="panel p-4">Optional AI provider credentials or a local Ollama endpoint</li>
                </ul>
              </div>

              <div className="space-y-4">
                <h3 className="text-xl font-semibold text-white">Installation</h3>
                <CodeSample code={installCurl} label="One-line install" />
                <CodeSample code={installPinned} label="Pinned release install" />
                <CodeSample code={installDocker} label="Docker run" />
                <CodeSample code={installSource} label="Build from source" />
              </div>
            </section>

            <section id="cli-reference" className="scroll-mt-24 space-y-8">
              <div>
                <h2 className="text-3xl font-semibold text-white">CLI Reference</h2>
                <p className="mt-4 max-w-3xl text-base leading-8 text-slate-400">
                  Stackdog currently centers on two commands: <code>serve</code> for the HTTP API and
                  <code> sniff</code> for continuous or one-shot log analysis.
                </p>
              </div>

              <div className="panel p-6">
                <h3 className="text-xl font-semibold text-white">stackdog serve</h3>
                <p className="mt-3 text-sm leading-7 text-slate-400">
                  Starts the HTTP API server on port 5000 by default. Use this mode when you want the
                  REST API and WebSocket event stream available for dashboards or external automation.
                </p>
                <pre className="mt-4">
                  <code>stackdog serve</code>
                </pre>
              </div>

              <div className="panel p-6">
                <h3 className="text-xl font-semibold text-white">stackdog sniff</h3>
                <p className="mt-3 text-sm leading-7 text-slate-400">
                  Sniffs and analyzes logs from Docker containers and system sources. It can run once,
                  archive data, enrich findings with AI providers, and push alerts to multiple channels.
                </p>
                <pre className="mt-4">
                  <code>stackdog sniff --once --ai-provider openai --ai-model gpt-4o-mini</code>
                </pre>
              </div>

              <div>
                <h3 className="mb-4 text-xl font-semibold text-white">sniff options</h3>
                <DocsTable headers={['Option', 'Description']} rows={sniffOptions} />
              </div>
            </section>

            <section id="rest-api" className="scroll-mt-24 space-y-8">
              <div>
                <h2 className="text-3xl font-semibold text-white">REST API Reference</h2>
                <p className="mt-4 max-w-3xl text-base leading-8 text-slate-400">
                  Build dashboards, status pages, or workflow automation on top of Stackdog&apos;s API and
                  WebSocket feed. The server listens on <code>http://localhost:5000</code> by default.
                </p>
              </div>
              <DocsTable headers={['Method', 'Endpoint', 'Purpose']} rows={apiRows} />
            </section>

            <section id="configuration" className="scroll-mt-24 space-y-8">
              <div>
                <h2 className="text-3xl font-semibold text-white">Configuration</h2>
                <p className="mt-4 max-w-3xl text-base leading-8 text-slate-400">
                  The sample environment file includes server settings, sniff behavior, AI provider
                  selection, and alert delivery channels. Start small, then layer in AI and automation.
                </p>
              </div>
              <DocsTable headers={['Variable', 'Example', 'Purpose']} rows={envRows} />
            </section>

            <section id="contributing" className="scroll-mt-24 space-y-5">
              <h2 className="text-3xl font-semibold text-white">Contributing &amp; GitHub</h2>
              <p className="max-w-3xl text-base leading-8 text-slate-400">
                Stackdog is open source and maintained in public. Review the repository, browse the
                changelog, or open an issue if you want to report bugs and propose features.
              </p>
              <div className="flex flex-wrap gap-4">
                <a
                  href="https://github.com/trydirect/stackdog"
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex items-center gap-2 rounded-full bg-cyan-500 px-5 py-3 text-sm font-semibold text-slate-950 transition hover:bg-cyan-400"
                >
                  GitHub repository
                  <ExternalLink className="h-4 w-4" />
                </a>
                <Link
                  href="/contact"
                  className="inline-flex items-center gap-2 rounded-full border border-slate-700 px-5 py-3 text-sm font-semibold text-slate-200 transition hover:border-cyan-400/60 hover:text-white"
                >
                  Contact the team
                </Link>
              </div>
            </section>
          </article>
        </div>
      </div>
    </main>
  );
}
