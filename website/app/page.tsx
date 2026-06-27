import type { Metadata } from 'next';
import Link from 'next/link';
import {
  ArrowRight,
  BellRing,
  Bot,
  Boxes,
  Cpu,
  Network,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  TerminalSquare,
  Workflow,
  Zap
} from 'lucide-react';
import CopyButton from '@/components/CopyButton';
import { getSiteUrl } from '@/lib/config';
import { buildHomeStructuredData, toJsonLd } from '@/lib/structured-data';

const installCommand =
  'curl -fsSL https://raw.githubusercontent.com/trydirect/stackdog/main/install.sh | sudo bash';

const stats = [
  { value: '<5%', label: 'CPU overhead' },
  { value: '10+', label: 'Threat signatures' },
  { value: '5', label: 'Alert channels' },
  { value: 'Real-time', label: 'Detection loop' }
];

const features = [
  {
    name: 'eBPF Monitoring',
    description:
      'Stream syscall activity from Docker workloads and Linux hosts with low-overhead kernel visibility.',
    icon: Cpu
  },
  {
    name: 'AI/ML Detection',
    description:
      'Combine Candle-powered anomaly detection with OpenAI and Ollama-compatible analysis workflows.',
    icon: Bot
  },
  {
    name: 'Log Sniffing & Analysis',
    description:
      'Discover logs, summarize incidents, archive evidence, and keep operators focused on what matters.',
    icon: Sparkles
  },
  {
    name: 'Automated Response',
    description:
      'Trigger nftables or iptables actions and quarantine suspicious containers before damage spreads.',
    icon: ShieldCheck
  },
  {
    name: 'Multi-Channel Alerts',
    description:
      'Route incidents to Slack, email, or webhooks for fast collaboration across SecOps and platform teams.',
    icon: BellRing
  },
  {
    name: 'Threat Scoring',
    description:
      'Prioritize with built-in signatures, heuristics, and scoring that helps teams act on the highest-risk events first.',
    icon: ShieldAlert
  }
];

const steps = [
  {
    title: 'Install',
    description:
      'Deploy Stackdog with a one-line install, a pinned release, or the published Docker image.',
    icon: TerminalSquare
  },
  {
    title: 'Monitor',
    description:
      'Collect syscalls, container telemetry, and logs while the rule engine and AI analyzers watch for anomalies.',
    icon: Network
  },
  {
    title: 'Respond',
    description:
      'Push alerts, score threats, and automatically firewall or quarantine suspicious workloads.',
    icon: Workflow
  }
];

const apiEndpoints = [
  'GET /api/security/status',
  'GET /api/threats',
  'GET /api/alerts',
  'GET /api/containers',
  'GET /api/logs/summaries',
  'WebSocket /ws'
];

const faqEntries = [
  {
    question: 'What is Stackdog Security?',
    answer:
      'Stackdog Security is a Rust-based runtime security platform for Docker containers and Linux servers. It combines eBPF monitoring, AI-assisted log analysis, threat scoring, and automated response in one stack.'
  },
  {
    question: 'How does Stackdog monitor containers?',
    answer:
      'Stackdog uses eBPF-based syscall monitoring and container-aware telemetry to observe workload behavior with low overhead. It also inspects logs and Docker metadata to enrich detections.'
  },
  {
    question: 'What AI providers does Stackdog support?',
    answer:
      'Stackdog can work with OpenAI-compatible APIs, local Ollama deployments, and Candle-powered Rust inference workflows. Teams can choose the provider that best matches their security and cost requirements.'
  },
  {
    question: 'Does Stackdog support Kubernetes?',
    answer:
      'Stackdog can already recognize Kubernetes-style container identifiers in runtime paths, but broader Kubernetes support is still on the roadmap. Today the primary deployment target is Docker containers and Linux servers.'
  },
  {
    question: 'How does Stackdog respond to threats?',
    answer:
      'Stackdog can score events, notify responders, push Slack or webhook alerts, update nftables or iptables rules, and quarantine suspicious containers as part of an automated response pipeline.'
  },
  {
    question: 'Is Stackdog open source?',
    answer:
      'Yes. Stackdog is open source on GitHub under the MIT license, so teams can audit the code, run it themselves, and contribute improvements.'
  },
  {
    question: 'What platforms does Stackdog support?',
    answer:
      'Stackdog is built for Docker containers and Linux servers. The core platform is written in Rust, and optional machine learning features use Candle for native Rust inference.'
  },
  {
    question: 'How do I get started?',
    answer:
      'Install Stackdog with the one-line script or Docker image, then review the CLI and API docs to start monitoring your infrastructure. From there you can configure AI providers, alert channels, and response actions.'
  }
];

export const metadata: Metadata = {
  title: 'AI-Powered Security for Docker Containers & Linux Servers',
  description:
    'Detect threats in real time with Stackdog Security. Monitor Docker containers and Linux servers with eBPF, AI-assisted log analysis, alerting, and automated response.',
  keywords: [
    'AI container security',
    'Docker runtime security',
    'Linux threat detection',
    'eBPF monitoring',
    'SOC automation',
    'Stackdog Security'
  ],
  alternates: {
    canonical: '/'
  },
  openGraph: {
    title: 'AI-Powered Security for Docker Containers & Linux Servers',
    description:
      'Real-time threat detection with eBPF monitoring, AI-assisted investigation, and automated containment for Docker and Linux workloads.',
    url: getSiteUrl() + '/'
  },
  twitter: {
    title: 'AI-Powered Security for Docker Containers & Linux Servers',
    description:
      'Real-time threat detection with eBPF monitoring, AI-assisted investigation, and automated containment for Docker and Linux workloads.'
  }
};

export default function HomePage() {
  return (
    <main>
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: toJsonLd(buildHomeStructuredData(faqEntries)) }}
      />

      <section className="section-shell pt-14 sm:pt-20">
        <div className="site-container">
          <div className="grid items-center gap-10 lg:grid-cols-[1.1fr_0.9fr]">
            <div>
              <span className="eyebrow">Stackdog Security v0.2.2</span>
              <h1 className="mt-6 max-w-4xl text-balance text-4xl font-semibold tracking-tight text-white sm:text-5xl lg:text-6xl">
                AI-Powered Security for Docker Containers &amp; Linux Servers
              </h1>
              <p className="mt-6 max-w-2xl text-lg leading-8 text-slate-400 sm:text-xl">
                Real-time threat detection using eBPF syscall monitoring. Zero-overhead security
                that scales with your containers.
              </p>
              <div className="mt-8 flex flex-wrap items-center gap-4">
                <Link
                  href="/docs"
                  className="inline-flex items-center gap-2 rounded-full bg-cyan-500 px-6 py-3 text-sm font-semibold text-slate-950 transition hover:bg-cyan-400"
                >
                  Get Started
                  <ArrowRight className="h-4 w-4" />
                </Link>
                <a
                  href="https://github.com/trydirect/stackdog"
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex items-center gap-2 rounded-full border border-slate-700 px-6 py-3 text-sm font-semibold text-slate-200 transition hover:border-cyan-400/50 hover:text-white"
                >
                  View on GitHub
                  <ArrowRight className="h-4 w-4" />
                </a>
              </div>
            </div>

            <div className="panel bg-grid p-6 sm:p-8">
              <div className="flex items-center justify-between gap-4">
                <div>
                  <p className="text-sm font-medium uppercase tracking-[0.2em] text-cyan-300">
                    Install in one line
                  </p>
                  <p className="mt-2 text-sm text-slate-400">
                    Ship runtime protection in minutes with the official installer.
                  </p>
                </div>
                <CopyButton text={installCommand} label="Copy Stackdog install command" />
              </div>
              <pre className="mt-6">
                <code>{installCommand}</code>
              </pre>
              <div className="mt-6 grid gap-4 sm:grid-cols-2">
                <div className="rounded-2xl border border-slate-800 bg-slate-950/70 p-4">
                  <p className="text-sm font-semibold text-white">Built for operators</p>
                  <p className="mt-2 text-sm text-slate-400">
                    Start the API with <code>stackdog serve</code> and stream live events through
                    <code> /ws</code>.
                  </p>
                </div>
                <div className="rounded-2xl border border-slate-800 bg-slate-950/70 p-4">
                  <p className="text-sm font-semibold text-white">AI on your terms</p>
                  <p className="mt-2 text-sm text-slate-400">
                    Pair local Ollama with OpenAI-compatible APIs or native Candle-backed models.
                  </p>
                </div>
              </div>
            </div>
          </div>

          <div className="panel mt-12 grid gap-6 px-6 py-5 sm:grid-cols-2 lg:grid-cols-4">
            {stats.map((stat) => (
              <div key={stat.label}>
                <p className="text-3xl font-semibold text-white">{stat.value}</p>
                <p className="mt-2 text-sm text-slate-400">{stat.label}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="section-shell">
        <div className="site-container">
          <span className="eyebrow">Feature overview</span>
          <h2 className="section-heading mt-6">Everything you need for runtime security at container speed</h2>
          <p className="section-copy">
            Stackdog combines runtime telemetry, AI-assisted analysis, and automated enforcement so
            small platform teams can investigate and contain threats without stitching together half
            a dozen tools.
          </p>
          <div className="mt-10 grid gap-6 md:grid-cols-2 xl:grid-cols-3">
            {features.map((feature) => {
              const Icon = feature.icon;
              return (
                <article key={feature.name} className="panel p-6">
                  <div className="inline-flex h-12 w-12 items-center justify-center rounded-2xl border border-cyan-500/20 bg-cyan-500/10 text-cyan-300">
                    <Icon className="h-5 w-5" />
                  </div>
                  <h3 className="mt-5 text-xl font-semibold text-white">{feature.name}</h3>
                  <p className="mt-3 text-sm leading-7 text-slate-400">{feature.description}</p>
                </article>
              );
            })}
          </div>
        </div>
      </section>

      <section className="section-shell border-y border-slate-800/70 bg-slate-900/30">
        <div className="site-container">
          <span className="eyebrow">How it works</span>
          <h2 className="section-heading mt-6">Install, monitor, and respond from one control loop</h2>
          <div className="mt-10 grid gap-6 lg:grid-cols-3">
            {steps.map((step, index) => {
              const Icon = step.icon;
              return (
                <article key={step.title} className="panel p-6">
                  <div className="flex items-center justify-between gap-4">
                    <div className="inline-flex h-12 w-12 items-center justify-center rounded-2xl border border-violet-500/20 bg-violet-500/10 text-violet-300">
                      <Icon className="h-5 w-5" />
                    </div>
                    <span className="text-sm font-medium text-slate-500">0{index + 1}</span>
                  </div>
                  <h3 className="mt-5 text-xl font-semibold text-white">{step.title}</h3>
                  <p className="mt-3 text-sm leading-7 text-slate-400">{step.description}</p>
                </article>
              );
            })}
          </div>
        </div>
      </section>

      <section className="section-shell">
        <div className="site-container grid gap-10 lg:grid-cols-[1fr_0.9fr] lg:items-start">
          <div>
            <span className="eyebrow">API &amp; CLI ready</span>
            <h2 className="section-heading mt-6">Stream incidents into your workflows in real time</h2>
            <p className="section-copy">
              Stackdog ships with a clean REST API and WebSocket feed, so you can wire dashboards,
              runbooks, ticket automation, or chatops around the same event stream that powers the
              built-in security engine.
            </p>
            <div className="mt-8 flex flex-wrap gap-3 text-sm text-slate-300">
              <span className="inline-flex items-center gap-2 rounded-full border border-slate-700 px-4 py-2">
                <Zap className="h-4 w-4 text-cyan-300" />
                stackdog serve on port 5000
              </span>
              <span className="inline-flex items-center gap-2 rounded-full border border-slate-700 px-4 py-2">
                <Boxes className="h-4 w-4 text-cyan-300" />
                WebSocket updates at /ws
              </span>
            </div>
          </div>

          <div className="panel p-6">
            <h3 className="text-lg font-semibold text-white">Core endpoints</h3>
            <ul className="mt-5 space-y-3">
              {apiEndpoints.map((endpoint) => (
                <li
                  key={endpoint}
                  className="flex items-center justify-between gap-4 rounded-2xl border border-slate-800 bg-slate-950/70 px-4 py-3 text-sm text-slate-200"
                >
                  <span>{endpoint}</span>
                  <ArrowRight className="h-4 w-4 text-slate-500" />
                </li>
              ))}
            </ul>
          </div>
        </div>
      </section>

      <section className="section-shell border-y border-slate-800/70 bg-slate-900/30">
        <div className="site-container">
          <span className="eyebrow">Frequently asked questions</span>
          <h2 className="section-heading mt-6">Answers for operators, platform teams, and security engineers</h2>
          <p className="section-copy">
            These common questions are optimized for both human readers and AI search engines, so
            buyers and assistants can quickly understand where Stackdog fits.
          </p>
          <div className="mt-10 grid gap-6 lg:grid-cols-2">
            {faqEntries.map((entry) => (
              <article key={entry.question} className="panel p-6">
                <h3 className="text-lg font-semibold text-white">{entry.question}</h3>
                <p className="mt-3 text-sm leading-7 text-slate-400">{entry.answer}</p>
              </article>
            ))}
          </div>
        </div>
      </section>

      <section className="section-shell">
        <div className="site-container">
          <div className="panel overflow-hidden border-cyan-500/20 bg-gradient-to-r from-cyan-500/10 via-slate-900 to-violet-500/10 p-8 sm:p-10">
            <div className="flex flex-col gap-6 lg:flex-row lg:items-center lg:justify-between">
              <div>
                <span className="eyebrow border-violet-500/30 bg-violet-500/10 text-violet-200">
                  Open source security
                </span>
                <h2 className="mt-5 text-3xl font-semibold tracking-tight text-white sm:text-4xl">
                  Start protecting your infrastructure today
                </h2>
                <p className="mt-4 max-w-2xl text-base text-slate-300 sm:text-lg">
                  Install Stackdog, connect your alerting channels, and bring AI-assisted runtime
                  detection to your Docker and Linux workloads.
                </p>
              </div>
              <a
                href="https://github.com/trydirect/stackdog"
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center justify-center gap-2 rounded-full bg-white px-6 py-3 text-sm font-semibold text-slate-950 transition hover:bg-slate-100"
              >
                View on GitHub
                <ArrowRight className="h-4 w-4" />
              </a>
            </div>
          </div>
        </div>
      </section>
    </main>
  );
}
